import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { ExpressAdapter } from '@nestjs/platform-express';
import request from 'supertest';
import express from 'express';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { decryptSecret } from '../src/common/encryption';

describe('Webhook Reliability Service (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let customerId: string;
  let customerBId: string;
  const API_KEY = 'e2e-test-api-key-' + Date.now();
  const API_KEY_B = 'e2e-test-api-key-b-' + Date.now();
  const STRIPE_SECRET = 'whsec_test_e2e_secret_' + Date.now();

  function generateStripeSignature(payload: string, secret: string): string {
    const timestamp = Math.floor(Date.now() / 1000);
    const signedPayload = `${timestamp}.${payload}`;
    const expectedSig = crypto
      .createHmac('sha256', secret)
      .update(signedPayload)
      .digest('hex');
    return `t=${timestamp},v1=${expectedSig}`;
  }

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    const expressApp = express();
    const adapter = new ExpressAdapter(expressApp);
    app = moduleFixture.createNestApplication(adapter, { rawBody: true });
    await app.init();

    prisma = app.get(PrismaService);

    // Create test customers
    const hashA = await bcrypt.hash(API_KEY, 10);
    const custA = await prisma.customers.create({ data: { api_key_hash: hashA } });
    customerId = custA.id;

    const hashB = await bcrypt.hash(API_KEY_B, 10);
    const custB = await prisma.customers.create({ data: { api_key_hash: hashB } });
    customerBId = custB.id;
  });

  afterAll(async () => {
    if (prisma) {
      try {
        await prisma.delivery_attempts.deleteMany({});
        await prisma.events.deleteMany({});
        await prisma.destinations.deleteMany({
          where: { customer_id: { in: [customerId, customerBId] } },
        });
        await prisma.customers.deleteMany({
          where: { id: { in: [customerId, customerBId] } },
        });
      } catch (e) {
        // ignore cleanup errors
      }
    }
    if (app) {
      await app.close();
    }
  });

  describe('Health Check', () => {
    it('GET /health should return ok status', async () => {
      const res = await request(app.getHttpServer()).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
      expect(res.body.postgres).toBe('ok');
      expect(res.body.redis).toBe('ok');
      expect(typeof res.body.queue_depth).toBe('number');
    });
  });

  describe('Admin - Create Destination', () => {
    it('POST /admin/destinations should require API key', async () => {
      const res = await request(app.getHttpServer())
        .post('/admin/destinations')
        .send({ target_url: 'https://example.com', secret: 'test' });
      expect(res.status).toBe(401);
    });

    it('POST /admin/destinations should create destination with encrypted secret', async () => {
      const res = await request(app.getHttpServer())
        .post('/admin/destinations')
        .set('X-Api-Key', API_KEY)
        .send({ target_url: 'https://httpbin.org/post', secret: STRIPE_SECRET });
      expect(res.status).toBe(201);
      expect(res.body.id).toBeDefined();
      expect(res.body.target_url).toBe('https://httpbin.org/post');

      // Verify secret is encrypted in DB
      const dest = await prisma.destinations.findUnique({ where: { id: res.body.id } });
      expect(dest).toBeDefined();
      expect(dest!.secret).not.toBe(STRIPE_SECRET);
      expect(dest!.secret).toContain(':'); // AES-256-GCM format has colons
      // Verify it decrypts correctly
      expect(decryptSecret(dest!.secret)).toBe(STRIPE_SECRET);
    });
  });

  describe('Ingest Endpoint', () => {
    let destinationId: string;

    beforeAll(async () => {
      const res = await request(app.getHttpServer())
        .post('/admin/destinations')
        .set('X-Api-Key', API_KEY)
        .send({ target_url: 'https://httpbin.org/post', secret: STRIPE_SECRET });
      destinationId = res.body.id;
    });

    it('should accept valid webhook and create event with pending status', async () => {
      const payload = JSON.stringify({ type: 'invoice.paid', data: { id: 'inv_' + Date.now() } });
      const signature = generateStripeSignature(payload, STRIPE_SECRET);

      const res = await request(app.getHttpServer())
        .post(`/ingest/${destinationId}`)
        .set('stripe-signature', signature)
        .set('Content-Type', 'application/json')
        .send(payload);

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('accepted');
      expect(res.body.event_id).toBeDefined();

      // Verify event in DB
      const event = await prisma.events.findUnique({ where: { id: res.body.event_id } });
      expect(event).toBeDefined();
      expect(event!.status).toBe('pending');
      expect(event!.signature_valid).toBe(true);
    });

    it('should detect duplicate payload within 24h', async () => {
      const payload = JSON.stringify({ type: 'invoice.paid', data: { id: 'inv_dedup_test' } });
      const sig1 = generateStripeSignature(payload, STRIPE_SECRET);

      const res1 = await request(app.getHttpServer())
        .post(`/ingest/${destinationId}`)
        .set('stripe-signature', sig1)
        .set('Content-Type', 'application/json')
        .send(payload);
      expect(res1.status).toBe(200);
      expect(res1.body.status).toBe('accepted');

      // Send same payload again
      const sig2 = generateStripeSignature(payload, STRIPE_SECRET);
      const res2 = await request(app.getHttpServer())
        .post(`/ingest/${destinationId}`)
        .set('stripe-signature', sig2)
        .set('Content-Type', 'application/json')
        .send(payload);
      expect(res2.status).toBe(200);
      expect(res2.body.status).toBe('duplicate');
      expect(res2.body.event_id).toBe(res1.body.event_id);
    });

    it('should reject missing stripe-signature header', async () => {
      const res = await request(app.getHttpServer())
        .post(`/ingest/${destinationId}`)
        .set('Content-Type', 'application/json')
        .send('{"type":"test"}');
      expect(res.status).toBe(400);
    });

    it('should reject invalid stripe signature', async () => {
      const payload = '{"type":"test"}';
      const res = await request(app.getHttpServer())
        .post(`/ingest/${destinationId}`)
        .set('stripe-signature', 't=123,v1=invalidsig')
        .set('Content-Type', 'application/json')
        .send(payload);
      expect(res.status).toBe(400);
    });
  });

  describe('Events Endpoint', () => {
    let destinationId: string;
    let eventId: string;

    beforeAll(async () => {
      const destRes = await request(app.getHttpServer())
        .post('/admin/destinations')
        .set('X-Api-Key', API_KEY)
        .send({ target_url: 'https://httpbin.org/post', secret: STRIPE_SECRET });
      destinationId = destRes.body.id;

      const payload = JSON.stringify({ type: 'charge.succeeded', data: { id: 'ch_event_test_' + Date.now() } });
      const sig = generateStripeSignature(payload, STRIPE_SECRET);
      const ingestRes = await request(app.getHttpServer())
        .post(`/ingest/${destinationId}`)
        .set('stripe-signature', sig)
        .set('Content-Type', 'application/json')
        .send(payload);
      eventId = ingestRes.body.event_id;
    });

    it('GET /events/:id should return event with delivery attempts', async () => {
      const res = await request(app.getHttpServer())
        .get(`/events/${eventId}`)
        .set('X-Api-Key', API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.id).toBe(eventId);
      expect(res.body.delivery_attempts).toBeDefined();
      expect(Array.isArray(res.body.delivery_attempts)).toBe(true);
    });

    it('Customer B should NOT access Customer A event (403)', async () => {
      const res = await request(app.getHttpServer())
        .get(`/events/${eventId}`)
        .set('X-Api-Key', API_KEY_B);
      expect(res.status).toBe(403);
    });

    it('POST /events/:id/replay should queue replay', async () => {
      const res = await request(app.getHttpServer())
        .post(`/events/${eventId}/replay`)
        .set('X-Api-Key', API_KEY);
      expect(res.status).toBe(202);
      expect(res.body.status).toBe('queued_for_replay');
      expect(res.body.event_id).toBe(eventId);

      // Verify event status updated
      const event = await prisma.events.findUnique({ where: { id: eventId } });
      expect(event!.status).toBe('replayed');
    });
  });

  describe('Security', () => {
    it('missing API key returns 401', async () => {
      const res = await request(app.getHttpServer()).get('/events/some-id');
      expect(res.status).toBe(401);
    });

    it('invalid API key returns 401', async () => {
      const res = await request(app.getHttpServer())
        .get('/events/some-id')
        .set('X-Api-Key', 'wrong-key');
      expect(res.status).toBe(401);
    });
  });
});
