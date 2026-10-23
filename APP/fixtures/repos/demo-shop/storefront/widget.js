export function renderBanner(el, campaign) {
  // Campaign copy comes from the CMS and is rendered as HTML.
  el.innerHTML = `<h2>${campaign.title}</h2><p>${campaign.body}</p>`;
}

export function formatPrice(pence, currency = "GBP") {
  return new Intl.NumberFormat("en-GB", { style: "currency", currency }).format(pence / 100);
}
