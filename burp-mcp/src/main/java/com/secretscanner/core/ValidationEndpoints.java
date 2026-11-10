package com.secretscanner.core;

import java.util.Map;
import java.util.TreeMap;

/**
 * Reference map of the verification endpoint each provider's LIVE validation check would contact.
 *
 * This is <em>reference data only</em> — the documented identity/verify endpoint each vendor
 * publishes (the same ones TruffleHog/Kingfisher use). It does not make any request; it lets the
 * Validation UI show the user exactly what a live check would hit, and lets self-hosted providers
 * carry a user-supplied base URL. The outbound call itself is the external live layer.
 *
 * Self-hosted providers use a {@code {base}} placeholder in the URL (e.g. a private GitLab); the
 * user supplies the base host and {@link #resolve} substitutes it. Providers that cannot be verified
 * with the credential alone (need a key+secret pair, an account ID, an OAuth exchange, request
 * signing, or have no identity endpoint) are recorded via {@link #none} so the UI explains why.
 */
public final class ValidationEndpoints {

    private ValidationEndpoints() {}

    /** method = HTTP verb (or "NONE"), url = endpoint (may contain {base}) or a reason when NONE. */
    public record Endpoint(String method, String url, boolean selfHosted) {
        public boolean verifiable() { return !"NONE".equals(method); }
        public String display() { return method + " " + url; }
    }

    // Keyed by the exact provider display name used in ValidationCatalog.
    private static final Map<String, Endpoint> MAP = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private static void put(String provider, String method, String url) { MAP.put(provider, new Endpoint(method, url, url.contains("{base}"))); }
    /** Provider that cannot be verified with the credential alone; {@code reason} is shown in the UI. */
    private static void none(String provider, String reason) { MAP.put(provider, new Endpoint("NONE", reason, false)); }
    static {
        // ── common providers (hand-curated) ────────────────────────────────
        put("GitHub",        "GET",  "https://api.github.com/user");
        put("AWS",           "POST", "https://sts.amazonaws.com/?Action=GetCallerIdentity");
        put("Stripe",        "GET",  "https://api.stripe.com/v1/account");
        put("OpenAI",        "GET",  "https://api.openai.com/v1/models");
        put("Anthropic",     "GET",  "https://api.anthropic.com/v1/models");
        put("OpenRouter",    "GET",  "https://openrouter.ai/api/v1/auth/key");
        put("Cohere",        "POST", "https://api.cohere.ai/v1/check-api-key");
        put("Hugging Face",  "GET",  "https://huggingface.co/api/whoami-v2");
        put("Slack",         "POST", "https://slack.com/api/auth.test");
        put("SendGrid",      "GET",  "https://api.sendgrid.com/v3/scopes");
        put("Twilio",        "GET",  "https://api.twilio.com/2010-04-01/Accounts.json");
        put("Mailgun",       "GET",  "https://api.mailgun.net/v3/domains");
        put("DigitalOcean",  "GET",  "https://api.digitalocean.com/v2/account");
        put("Cloudflare",    "GET",  "https://api.cloudflare.com/client/v4/user/tokens/verify");
        put("Heroku",        "GET",  "https://api.heroku.com/account");
        put("npm",           "GET",  "https://registry.npmjs.org/-/whoami");
        put("Datadog",       "GET",  "https://api.datadoghq.com/api/v1/validate");
        put("PagerDuty",     "GET",  "https://api.pagerduty.com/users");
        put("Dropbox",       "POST", "https://api.dropboxapi.com/2/users/get_current_account");
        put("HubSpot",       "GET",  "https://api.hubapi.com/account-info/v3/details");
        put("Notion",        "GET",  "https://api.notion.com/v1/users/me");
        put("Linear",        "POST", "https://api.linear.app/graphql");
        put("Discord",       "GET",  "https://discord.com/api/v10/users/@me");
        put("Telegram",      "GET",  "https://api.telegram.org/bot{token}/getMe");
        put("Figma",         "GET",  "https://api.figma.com/v1/me");
        put("Vercel",        "GET",  "https://api.vercel.com/v2/user");
        put("Netlify",       "GET",  "https://api.netlify.com/api/v1/user");
        put("CircleCI",      "GET",  "https://circleci.com/api/v2/me");
        put("Postman",       "GET",  "https://api.getpostman.com/me");
        put("Airtable",      "GET",  "https://api.airtable.com/v0/meta/whoami");
        put("Asana",         "GET",  "https://app.asana.com/api/1.0/users/me");
        put("Intercom",      "GET",  "https://api.intercom.io/me");
        put("AssemblyAI",    "GET",  "https://api.assemblyai.com/v2/transcript");
        put("Deepgram",      "GET",  "https://api.deepgram.com/v1/projects");
        put("ElevenLabs",    "GET",  "https://api.elevenlabs.io/v1/user");
        put("Fastly",        "GET",  "https://api.fastly.com/current_user");
        put("ngrok",         "GET",  "https://api.ngrok.com/credentials");
        put("GitLab",             "GET",  "{base}/api/v4/user");
        put("Mattermost",         "GET",  "{base}/api/v4/users/me");
        put("JFrog Artifactory",  "GET",  "{base}/artifactory/api/system/ping");
        put("Gitea",              "GET",  "{base}/api/v1/user");
        put("Grafana",            "GET",  "{base}/api/user");
        put("SonarQube",          "GET",  "{base}/api/authentication/validate");
        put("HashiCorp Vault",    "GET",  "{base}/v1/auth/token/lookup-self");
        put("Sourcegraph",        "POST", "{base}/.api/graphql");
        put("Zendesk",            "GET",  "{base}/api/v2/users/me.json");
        put("Okta",               "GET",  "{base}/api/v1/users/me");
        put("Databricks",         "GET",  "{base}/api/2.0/clusters/list");
        put("Shopify",            "GET",  "{base}/admin/api/2024-01/shop.json");
        // ── compiled from provider API docs (research 2026-10-25) ──────────
        put("AbuseIPDB", "GET", "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8");
        put("Adafruit IO", "GET", "https://io.adafruit.com/api/v2/user");
        put("Aiven", "GET", "https://api.aiven.io/v1/me");
        put("Apify", "GET", "https://api.apify.com/v2/users/me");
        put("Apollo", "GET", "https://api.apollo.io/api/v1/auth/health");
        put("Asaas", "GET", "https://api.asaas.com/v3/myAccount/status");
        put("Atlassian", "GET", "https://api.atlassian.com/me");
        put("Atlassian Jira", "GET", "{base}/rest/api/2/myself");
        put("Auth0", "GET", "{base}/userinfo");
        put("Beamer", "GET", "https://api.getbeamer.com/v0/posts");
        put("Bitbucket", "GET", "https://api.bitbucket.org/2.0/user");
        put("Bitly", "GET", "https://api-ssl.bitly.com/v4/user");
        put("Bitrise", "GET", "https://api.bitrise.io/v0.1/me");
        put("Brave Search", "GET", "https://api.search.brave.com/res/v1/web/search?q=test");
        put("Brevo", "GET", "https://api.brevo.com/v3/account");
        put("Buildkite", "GET", "https://api.buildkite.com/v2/access-token");
        put("Canva", "GET", "https://api.canva.com/rest/v1/users/me");
        put("Cartesia", "GET", "https://api.cartesia.ai/voices");
        put("Cerebras", "GET", "https://api.cerebras.ai/v1/models");
        put("Checkout.com", "GET", "https://api.checkout.com/workflows");
        put("Cisco Webex", "GET", "https://webexapis.com/v1/people/me");
        put("Civo", "GET", "https://api.civo.com/v2/instances");
        put("Clerk", "GET", "https://api.clerk.com/v1/users");
        put("ClickUp", "GET", "https://api.clickup.com/api/v2/user");
        put("Cloudsmith", "GET", "https://api.cloudsmith.io/v1/user/self/");
        put("CockroachDB", "GET", "https://cockroachlabs.cloud/api/v1/clusters");
        put("Contentful", "GET", "https://api.contentful.com/users/me");
        put("Couchbase", "GET", "https://cloudapi.cloud.couchbase.com/v4/organizations");
        put("Cursor", "GET", "https://api.cursor.com/v1/me");
        put("DataStax Astra", "GET", "https://api.astra.datastax.com/v2/databases");
        put("Databento", "GET", "https://hist.databento.com/v0/metadata.list_datasets");
        put("DeepSeek", "GET", "https://api.deepseek.com/user/balance");
        put("Defined Networking", "GET", "https://api.defined.net/v2/whoami");
        put("Devin", "GET", "https://api.devin.ai/v1/sessions");
        put("Doppler", "GET", "https://api.doppler.com/v3/me");
        put("Drone CI", "GET", "{base}/api/user");
        put("Duffel", "GET", "https://api.duffel.com/air/orders");
        put("Dynatrace", "POST", "{base}/api/v2/apiTokens/lookup");
        put("EasyPost", "GET", "https://api.easypost.com/v2/users");
        put("Elastic", "GET", "{base}/_security/_authenticate");
        put("Etsy", "GET", "https://openapi.etsy.com/v3/application/openapi-ping");
        put("Finnhub", "GET", "https://finnhub.io/api/v1/quote?symbol=AAPL&token=KEY");
        put("Flutterwave", "GET", "https://api.flutterwave.com/v3/subaccounts");
        put("Fly.io", "POST", "https://api.fly.io/graphql");
        put("Frame.io", "GET", "https://api.frame.io/v2/me");
        put("FreshBooks", "GET", "https://api.freshbooks.com/auth/api/v1/users/me");
        put("Freshdesk", "GET", "{base}/api/v2/agents/me");
        put("FullStory", "GET", "https://api.fullstory.com/me");
        put("Gitter", "GET", "https://api.gitter.im/v1/user/me");
        put("GoCardless", "GET", "https://api.gocardless.com/creditors");
        put("Google", "GET", "https://oauth2.googleapis.com/tokeninfo?access_token={token}");
        put("Groq", "GET", "https://api.groq.com/openai/v1/models");
        put("Gumroad", "GET", "https://api.gumroad.com/v2/user");
        put("HashiCorp Terraform", "GET", "https://app.terraform.io/api/v2/account/details");
        put("Highnote", "POST", "https://api.us.highnote.com/graphql");
        put("Honeycomb", "GET", "https://api.honeycomb.io/1/auth");
        put("Hunter.io", "GET", "https://api.hunter.io/v2/account?api_key=KEY");
        put("InfluxDB", "GET", "{base}/api/v2/me");
        put("Infomaniak", "GET", "https://api.infomaniak.com/2/profile");
        put("Instantly", "GET", "https://api.instantly.ai/api/v2/workspaces/current");
        put("JumpCloud", "GET", "https://console.jumpcloud.com/api/systemusers");
        put("Kagi", "GET", "https://kagi.com/api/v1/search?q=test");
        put("Klaviyo", "GET", "https://a.klaviyo.com/api/accounts/");
        put("Kubernetes", "POST", "{base}/apis/authentication.k8s.io/v1/selfsubjectreviews");
        put("LangSmith", "GET", "https://api.smith.langchain.com/api/v1/workspaces");
        put("Langchain", "GET", "https://api.smith.langchain.com/api/v1/workspaces");
        put("LaunchDarkly", "GET", "https://app.launchdarkly.com/api/v2/caller-identity");
        put("Lichess", "GET", "https://lichess.org/api/account");
        put("LightOn", "GET", "https://paradigm.lighton.ai/api/v2/models");
        put("LinkedIn", "GET", "https://api.linkedin.com/v2/userinfo");
        put("Llama", "GET", "https://api.llama.com/compat/v1/models");
        put("Lob", "GET", "https://api.lob.com/v1/addresses");
        put("MailerSend", "GET", "https://api.mailersend.com/v1/domains");
        put("Mailchimp", "GET", "https://{dc}.api.mailchimp.com/3.0/");
        put("Mapbox", "GET", "https://api.mapbox.com/tokens/v2?access_token={token}");
        put("Mem0", "GET", "https://api.mem0.ai/v1/ping/");
        put("Mercury", "GET", "https://api.mercury.com/api/v1/accounts");
        put("Mergify", "GET", "https://api.mergify.com/v1/application");
        put("MessageBird", "GET", "https://rest.messagebird.com/balance");
        put("Meta", "GET", "https://graph.facebook.com/me?access_token={token}");
        put("MiniMax", "GET", "https://api.minimax.io/v1/models");
        put("Miro", "GET", "https://api.miro.com/v1/oauth-token");
        put("Mistral AI", "GET", "https://api.mistral.ai/v1/models");
        put("Moonshot Kimi", "GET", "https://api.moonshot.ai/v1/models");
        put("NVIDIA", "GET", "https://integrate.api.nvidia.com/v1/models");
        put("Neon", "GET", "https://console.neon.tech/api/v2/users/me");
        put("New Relic", "POST", "https://api.newrelic.com/graphql");
        put("New York Times", "GET", "https://api.nytimes.com/svc/search/v2/articlesearch.json?api-key=KEY");
        put("Octopus Deploy", "GET", "{base}/api/users/me");
        put("OneSignal", "GET", "https://api.onesignal.com/apps");
        put("OpenShift", "GET", "{base}/apis/user.openshift.io/v1/users/~");
        put("OpenWeather", "GET", "https://api.openweathermap.org/data/2.5/weather?q=London&appid=KEY");
        put("Opsgenie", "GET", "https://api.opsgenie.com/v2/account");
        put("Paddle", "GET", "https://api.paddle.com/event-types");
        put("Paystack", "GET", "https://api.paystack.co/balance");
        put("Perplexity", "GET", "https://api.perplexity.ai/v1/models");
        put("Persona", "GET", "https://api.withpersona.com/api/v1/accounts");
        put("Pinecone", "GET", "https://api.pinecone.io/indexes");
        put("Pinterest", "GET", "https://api.pinterest.com/v5/user_account");
        put("Polar", "GET", "https://api.polar.sh/v1/oauth2/userinfo");
        put("PostHog", "GET", "{base}/api/users/@me/");
        put("Postmark", "GET", "https://api.postmarkapp.com/server");
        put("Private AI", "GET", "https://api.getlimina.ai/community/v4/healthz");
        put("Proof", "GET", "https://api.proof.com/v1/notaries/");
        put("Pulumi", "GET", "https://api.pulumi.com/api/user");
        put("Rainforest", "GET", "https://api.rainforestpay.com/v1/merchants");
        put("ReadMe", "GET", "https://api.readme.com/v2/projects/me");
        put("Redirect.pizza", "GET", "https://redirect.pizza/api/v1/redirects");
        put("Render", "GET", "https://api.render.com/v1/owners");
        put("Replicate", "GET", "https://api.replicate.com/v1/account");
        put("Resend", "GET", "https://api.resend.com/api-keys");
        put("Retell", "GET", "https://api.retellai.com/get-concurrency");
        put("Rootly", "GET", "https://api.rootly.com/v1/users/me");
        put("RubyGems", "GET", "https://rubygems.org/api/v1/gems.json");
        put("Runpod", "POST", "https://api.runpod.io/graphql");
        put("SSLMate", "GET", "https://sslmate.com/api/v3/monitoring/monitored_domains");
        put("Samsara", "GET", "https://api.samsara.com/fleet/vehicles");
        put("Scaleway", "GET", "https://api.scaleway.com/instance/v1/zones/fr-par-1/servers");
        put("Scalr", "GET", "{base}/api/iacp/v3/account-users");
        put("Sendinblue", "GET", "https://api.sendinblue.com/v3/account");
        put("Sentry", "GET", "https://sentry.io/api/0/organizations/");
        put("Shippo", "GET", "https://api.goshippo.com/addresses/");
        put("Snyk", "GET", "https://api.snyk.io/rest/self?version=2024-10-15");
        put("Splunk", "GET", "{base}/services/authentication/current-context");
        put("Square", "GET", "https://connect.squareup.com/v2/merchants");
        put("Stability AI", "GET", "https://api.stability.ai/v1/user/account");
        put("Supabase", "GET", "https://api.supabase.com/v1/projects");
        put("Tailscale", "GET", "https://api.tailscale.com/api/v2/tailnet/-/devices");
        put("Telnyx", "GET", "https://api.telnyx.com/v2/balance");
        put("Thunderstore", "GET", "https://thunderstore.io/api/experimental/current-user/");
        put("Togetherai", "GET", "https://api.together.ai/v1/models");
        put("Travis CI", "GET", "https://api.travis-ci.com/user");
        put("Twitch", "GET", "https://id.twitch.tv/oauth2/validate");
        put("Typeform", "GET", "https://api.typeform.com/me");
        put("Unkey", "POST", "https://api.unkey.com/v2/workspace.getLimits");
        put("UpCloud", "GET", "https://api.upcloud.com/1.3/account");
        put("Upstage", "GET", "https://api.upstage.ai/v1/models");
        put("Val", "GET", "https://api.val.town/v1/me");
        put("Virustotal", "GET", "https://www.virustotal.com/api/v3/users/{apikey}");
        put("Voyageai", "GET", "https://api.voyageai.com/v1/batches");
        put("Vultr", "GET", "https://api.vultr.com/v2/account");
        put("WakaTime", "GET", "https://wakatime.com/api/v1/users/current");
        put("Weatherstack", "GET", "https://api.weatherstack.com/current?access_key=KEY&query=London");
        put("Weights", "POST", "https://api.wandb.ai/graphql");
        put("Workato", "GET", "https://www.workato.com/api/users/me");
        put("Workos", "GET", "https://api.workos.com/organizations");
        put("Xendit", "GET", "https://api.xendit.co/balance");
        put("Yandex", "GET", "https://login.yandex.ru/info");
        put("eBay", "GET", "https://apiz.ebay.com/commerce/identity/v1/user/");
        put("monday.com", "POST", "https://api.monday.com/v2");
        put("xAI", "GET", "https://api.x.ai/v1/models");
        // ── not verifiable with the credential alone (reason shown in UI) ──
        none("1Password", "no verify API");
        none("Adobe", "needs OAuth token exchange");
        none("Aikido", "needs OAuth token exchange");
        none("Algolia", "needs app ID");
        none("Alibaba Cloud", "needs request signing");
        none("Amplitude", "needs key+secret pair");
        none("Authress", "no verify API");
        none("Bittrex", "needs request signing");
        none("Braintree", "needs key+secret pair");
        none("BrowserStack", "needs username");
        none("Canadian Digital Service", "needs request signing");
        none("ClickHouse", "needs key+secret pair");
        none("Clojars", "no verify API");
        none("Cloudinary", "needs key+secret pair");
        none("Codecov", "needs account ID");
        none("Coinbase", "needs request signing");
        none("ConfigCat", "needs key+secret pair");
        none("Confluent", "needs key+secret pair");
        none("Coveralls", "no verify API");
        none("Crates.io", "no verify API");
        none("CyberArk", "needs host");
        none("Data.gov", "no verify API");
        none("Deno Deploy", "needs an account/project ID");
        none("DevCycle", "needs username");
        none("Disqus", "needs OAuth token exchange");
        none("Docker Hub", "needs username");
        none("Endor Labs", "needs key+secret pair");
        none("Exoscale", "needs request signing");
        none("Fal.ai", "no verify API");
        none("Finicity", "needs key+secret pair");
        none("Firebase", "no verify API");
        none("Flexmonster", "no verify API");
        none("Flickr", "needs request signing");
        none("Freemius", "needs request signing");
        none("Generic (Basic auth)", "no verify API");
        none("Generic (CryptoJS key)", "no verify API");
        none("Generic (GUID token)", "no verify API");
        none("Generic (JWT)", "no verify API");
        none("Generic (OAuth resource)", "no verify API");
        none("Generic (certificate thumbprint)", "no verify API");
        none("Generic (password hash)", "no verify API");
        none("Generic (private key)", "no verify API");
        none("Google Cloud", "needs OAuth token exchange");
        none("Greptile", "needs key+secret pair");
        none("Harness", "needs account ID");
        none("IBM Cloud", "needs OAuth token exchange");
        none("Infracost", "no verify API");
        none("Intra 42", "needs OAuth token exchange");
        none("Ionic", "no verify API");
        none("Jenkins", "needs username");
        none("Kraken", "needs request signing");
        none("KuCoin", "needs request signing");
        none("Langfuse", "needs key+secret pair");
        none("Lark", "needs OAuth token exchange");
        none("Looker", "needs key+secret pair");
        none("MaxMind", "needs account ID");
        none("Microsoft Azure", "needs OAuth token exchange");
        none("Microsoft Entra ID", "needs OAuth token exchange");
        none("Microsoft Teams", "needs OAuth token exchange");
        none("Midtrans", "no verify API");
        none("MongoDB", "needs key+secret pair");
        none("Mux", "needs key+secret pair");
        none("NuGet", "no verify API");
        none("Nylas", "no verify API");
        none("OVH", "needs request signing");
        none("Ollama", "no verify API");
        none("Onfido", "needs region");
        none("PayPal", "needs OAuth token exchange");
        none("Plaid", "needs key+secret pair");
        none("PlanetScale", "needs an account/project ID");
        none("Plivo", "needs an account/project ID");
        none("Polymarket", "needs request signing");
        none("Prefect", "needs account ID");
        none("PyPI", "no verify API");
        none("Ramp", "needs OAuth token exchange");
        none("RapidAPI", "no verify API");
        none("Razorpay", "needs key+secret pair");
        none("Salesforce", "needs instance host");
        none("Scalingo", "needs OAuth token exchange");
        none("Segment", "no verify API");
        none("Sendbird", "needs an account/project ID");
        none("SettleMint", "no verify API");
        none("Sidekiq", "needs key+secret pair");
        none("Snowflake", "needs an account/project ID");
        none("Spotify", "needs OAuth token exchange");
        none("Sumo Logic", "needs key+secret pair");
        none("Tableau", "needs key+secret pair");
        none("Upstash", "needs an account/project ID");
        none("WireGuard", "no verify API");
        none("Wiz", "needs OAuth token exchange");
        none("WooCommerce", "needs key+secret pair");
        none("X (Twitter)", "needs request signing");
        none("Z.ai", "no verify API");
        none("Zoho", "needs OAuth token exchange");
        none("Zoom", "needs OAuth token exchange");
        none("Zuplo", "needs account ID");
        none("age", "no verify API");
    }

    /** Endpoint for a provider, or null if the provider is not catalogued. */
    public static Endpoint forProvider(String provider) {
        return provider == null ? null : MAP.get(provider);
    }

    /** How the credential attaches to the verify request: scheme + optional header/param name. */
    public record Auth(LiveValidator.Auth scheme, String detail) {}

    // Default is a Bearer token in the Authorization header (covers GitHub, Stripe, OpenAI, and most
    // vendor tokens). Only providers that attach the key differently are listed here.
    private static final Map<String, Auth> AUTH = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private static void auth(String provider, LiveValidator.Auth scheme, String detail) { AUTH.put(provider, new Auth(scheme, detail)); }
    static {
        auth("VirusTotal",  LiveValidator.Auth.HEADER, "x-apikey");
        auth("Cursor",      LiveValidator.Auth.BASIC_USER, "");
        auth("Mailgun",     LiveValidator.Auth.BASIC_USER, "");   // key as basic-auth password-style; api user
        auth("Postmark",    LiveValidator.Auth.HEADER, "X-Postmark-Server-Token");
        auth("MaxMind",     LiveValidator.Auth.BASIC_USER, "");
        auth("AbuseIPDB",   LiveValidator.Auth.HEADER, "Key");
    }

    /** How to attach the credential for a provider; defaults to a Bearer Authorization header. */
    public static Auth authFor(String provider) {
        Auth a = provider == null ? null : AUTH.get(provider);
        return a != null ? a : new Auth(LiveValidator.Auth.BEARER, "");
    }

    /** A callable endpoint: concrete HTTP method + URL, ready for a live check. */
    public record Call(String method, String url) {}

    /**
     * The concrete, callable endpoint for a provider honouring any user {@code override}/base-URL, or
     * null when there is nothing to call — provider unknown, not verifiable, or a self-hosted
     * template whose base URL the user has not supplied yet.
     */
    public static Call resolveCall(String provider, String override) {
        String r = resolve(provider, override);
        if (r.isEmpty() || r.startsWith("(not verifiable") || r.contains("{base}")
                || r.endsWith("(set your base URL)")) return null;
        int sp = r.indexOf(' ');
        if (sp <= 0) return null;
        String method = r.substring(0, sp).trim();
        String url    = r.substring(sp + 1).trim();
        if (url.isEmpty() || !(url.startsWith("http://") || url.startsWith("https://"))) return null;
        return new Call(method, url);
    }

    /** True when the provider's endpoint needs a user-supplied base URL (self-hosted / custom domain). */
    public static boolean isSelfHosted(String provider) {
        Endpoint e = forProvider(provider);
        return e != null && e.selfHosted();
    }

    private static final java.util.regex.Pattern METHOD_PREFIX =
            java.util.regex.Pattern.compile("(?i)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\\s+(\\S.*)$");

    /**
     * Human-readable endpoint for the UI, honouring a user {@code override} when given.
     *
     * The override (from the "Validation endpoints" settings box) can be:
     *   - a full endpoint, "METHOD https://host/path" — used verbatim for ANY provider, including
     *     ones with a fixed public endpoint or none at all (e.g. set a check for a "not verifiable"
     *     provider, or point one at an internal proxy);
     *   - a bare host, "https://host" — substituted into a self-hosted provider's {@code {base}}
     *     template, or (for a non-self-hosted provider) used as the full endpoint with GET.
     *
     * With no override: a verifiable provider returns method + URL ({@code {base}} self-hosted
     * providers show the template plus a hint until a base URL is set); a non-verifiable provider
     * returns "(not verifiable: reason)"; an unknown provider returns "".
     */
    public static String resolve(String provider, String override) {
        Endpoint e = forProvider(provider);
        if (override != null && !override.isBlank()) {
            String ov = override.trim();
            java.util.regex.Matcher m = METHOD_PREFIX.matcher(ov);
            if (m.matches())                                   // full "METHOD url" override
                return m.group(1).toUpperCase(java.util.Locale.ROOT) + " " + m.group(2).trim();
            if (e != null && e.selfHosted())                   // bare host into the {base} template
                return e.method() + " " + e.url().replace("{base}", ov.replaceAll("/+$", ""));
            return "GET " + ov;                                // bare URL = full endpoint for any other provider
        }
        if (e == null) return "";
        if (!e.verifiable()) return "(not verifiable: " + e.url() + ")";
        if (!e.selfHosted()) return e.display();
        return e.display() + "  (set your base URL)";
    }
}
