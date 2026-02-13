import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { stripe, PLANS, type PlanKey, type SubscriptionData } from '$lib/server/stripe';

export const GET: RequestHandler = async ({ locals }) => {
  const user = locals.user;
  if (!user) return new Response('Unauthorized', { status: 401 });

  const developerAccount = locals.developerAccount;
  if (!developerAccount) {
    return json({ error: 'Developer account not found' }, { status: 404 });
  }

  const plan = (developerAccount.plan as PlanKey) || 'FREE';
  const planConfig = PLANS[plan];

  const result: {
    plan: PlanKey;
    planName: string;
    billingState: string;
    mauLimit: number;
    appLimit: number;
    subscription: SubscriptionData | null;
  } = {
    plan,
    planName: planConfig.name,
    billingState: developerAccount.billingState,
    mauLimit: developerAccount.mauLimit,
    appLimit: developerAccount.appLimit,
    subscription: null,
  };

  // Fetch live subscription details from Stripe if customer exists
  if (developerAccount.stripeCustomerId && developerAccount.stripeSubscriptionId) {
    try {
      const sub = await stripe.subscriptions.retrieve(developerAccount.stripeSubscriptionId, {
        expand: ['default_payment_method'],
      });

      let paymentMethod: { brand: string; last4: string } | null = null;
      if (sub.default_payment_method && typeof sub.default_payment_method !== 'string') {
        const pm = sub.default_payment_method;
        if (pm.card) {
          paymentMethod = {
            brand: pm.card.brand,
            last4: pm.card.last4,
          };
        }
      }

      result.subscription = {
        subscriptionId: sub.id,
        status: sub.status,
        priceId: sub.items.data[0]?.price.id || '',
        currentPeriodStart: sub.current_period_start,
        currentPeriodEnd: sub.current_period_end,
        cancelAtPeriodEnd: sub.cancel_at_period_end,
        paymentMethod,
      };
    } catch {
      // Subscription may have been deleted in Stripe
    }
  }

  return json(result);
};
