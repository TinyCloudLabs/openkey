import type { PageServerLoad } from './$types';
import { stripe, PLANS, type PlanKey, type SubscriptionData } from '$lib/server/stripe';
import { redirect } from '@sveltejs/kit';

export const load: PageServerLoad = async ({ locals }) => {
  const user = locals.user;
  if (!user) throw redirect(302, '/');

  const developerAccount = locals.developerAccount;
  if (!developerAccount) throw redirect(302, '/');

  const plan = (developerAccount.plan as PlanKey) || 'FREE';
  const planConfig = PLANS[plan];

  let subscription: SubscriptionData | null = null;

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

      subscription = {
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

  return {
    plan,
    planName: planConfig.name,
    billingState: developerAccount.billingState,
    mauLimit: developerAccount.mauLimit,
    appLimit: developerAccount.appLimit,
    subscription,
    plans: PLANS,
  };
};
