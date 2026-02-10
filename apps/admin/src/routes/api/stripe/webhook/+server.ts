import type { RequestHandler } from './$types';
import { stripe, syncStripeDataToDb } from '$lib/server/stripe';
import { db } from '$lib/server/db';

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

export const POST: RequestHandler = async ({ request }) => {
  if (!WEBHOOK_SECRET) {
    return new Response('Webhook secret not configured', { status: 500 });
  }

  const body = await request.text();
  const signature = request.headers.get('stripe-signature');

  if (!signature) {
    return new Response('Missing stripe-signature header', { status: 400 });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(body, signature, WEBHOOK_SECRET);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return new Response(`Webhook signature verification failed: ${message}`, { status: 400 });
  }

  // Extract customer ID from the event
  let stripeCustomerId: string | null = null;

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      stripeCustomerId = typeof session.customer === 'string'
        ? session.customer
        : session.customer?.id ?? null;
      break;
    }
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      stripeCustomerId = typeof subscription.customer === 'string'
        ? subscription.customer
        : subscription.customer?.id ?? null;
      break;
    }
    case 'invoice.paid':
    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      stripeCustomerId = typeof invoice.customer === 'string'
        ? invoice.customer
        : invoice.customer?.id ?? null;
      break;
    }
    default:
      // Unhandled event type - return 200 to acknowledge receipt
      return new Response('OK', { status: 200 });
  }

  if (stripeCustomerId) {
    try {
      await syncStripeDataToDb(db, stripeCustomerId);
    } catch (err) {
      console.error(`Failed to sync Stripe data for customer ${stripeCustomerId}:`, err);
      // Return 500 so Stripe retries
      return new Response('Failed to process webhook', { status: 500 });
    }
  }

  return new Response('OK', { status: 200 });
};
