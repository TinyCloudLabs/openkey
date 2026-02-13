import Stripe from 'stripe';
import { env } from '$env/dynamic/private';

let _stripe: Stripe;

function getStripe(): Stripe {
  if (!_stripe) {
    if (!env.STRIPE_SECRET_KEY) {
      throw new Error('STRIPE_SECRET_KEY is required');
    }
    _stripe = new Stripe(env.STRIPE_SECRET_KEY);
  }
  return _stripe;
}

// Lazy-initialized Stripe client - only throws when actually used
export const stripe = new Proxy({} as Stripe, {
  get(_target, prop) {
    return (getStripe() as any)[prop];
  },
});

// Plan configuration - Price IDs from Stripe Dashboard
export const PLANS = {
  FREE: { name: 'Free', priceId: null, mauLimit: 1000, appLimit: 3 },
  PRO: { name: 'Pro', priceId: env.STRIPE_PRICE_ID_PRO || '', mauLimit: 10000, appLimit: 10 },
  SCALE: { name: 'Scale', priceId: env.STRIPE_PRICE_ID_SCALE || '', mauLimit: 100000, appLimit: 50 },
  ENTERPRISE: { name: 'Enterprise', priceId: env.STRIPE_PRICE_ID_ENTERPRISE || '', mauLimit: -1, appLimit: -1 },
} as const;

export type PlanKey = keyof typeof PLANS;

// Subscription data shape stored/retrieved
export interface SubscriptionData {
  subscriptionId: string;
  status: string;
  priceId: string;
  currentPeriodStart: number;
  currentPeriodEnd: number;
  cancelAtPeriodEnd: boolean;
  paymentMethod: { brand: string; last4: string } | null;
}

// Sync stripe data to DeveloperAccount in DB
export async function syncStripeDataToDb(db: any, stripeCustomerId: string) {
  const subscriptions = await stripe.subscriptions.list({
    customer: stripeCustomerId,
    limit: 1,
    status: 'all',
  });

  const sub = subscriptions.data[0];
  if (!sub) return;

  // Determine plan from priceId
  const priceId = sub.items.data[0]?.price.id;
  let plan: PlanKey = 'FREE';
  for (const [key, config] of Object.entries(PLANS)) {
    if (config.priceId === priceId) {
      plan = key as PlanKey;
      break;
    }
  }

  // Determine billing state
  let billingState = 'FREE';
  if (sub.status === 'active') billingState = 'ACTIVE';
  else if (sub.status === 'past_due') billingState = 'PAST_DUE';
  else if (sub.status === 'canceled') billingState = 'CANCELLED';

  await db.developerAccount.update({
    where: { stripeCustomerId },
    data: {
      plan,
      billingState,
      mauLimit: PLANS[plan].mauLimit,
      appLimit: PLANS[plan].appLimit,
      stripeSubscriptionId: sub.id,
    },
  });
}
