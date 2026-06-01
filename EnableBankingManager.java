
package com.couplefinance.data;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * EnableBankingManager — Client REST pour l'API Enable Banking (Open Banking DSP2).
 *
 * Remplacement drop-in de GoCardlessManager pour usage personnel gratuit.
 * Enable Banking permet de connecter ses propres comptes bancaires sans contrat.
 *
 * ── Pourquoi Enable Banking ? ─────────────────────────────────────────────
 *   GoCardless a fermé les nouvelles inscriptions en juillet 2025.
 *   Enable Banking offre un mode restreint gratuit : seuls les comptes que tu
 *   as toi-même liés sont accessibles. Parfait pour un usage privé à 2 personnes.
 *
 * ── Prérequis (à faire une seule fois) ────────────────────────────────────
 *   1. Créer un compte sur https://enablebanking.com/sign-in/
 *   2. Dans le panneau de contrôle → "Applications" → "New application"
 *   3. Choisir "PRODUCTION", cocher "Generate in the browser (SubtleCrypto)"
 *   4. Télécharger la clé privée générée (fichier .pem)
 *   5. Noter l'Application ID affiché
 *   6. Cliquer "Activate by linking accounts" → lier ton compte bancaire
 *   7. Saisir Application ID + contenu du fichier .pem dans CoupleFinance
 *
 * ── Authentification ──────────────────────────────────────────────────────
 *   Chaque requête porte un JWT RS256 signé avec la clé privée :
 *     Header : {"alg":"RS256","kid":"<application_id>"}
 *     Payload: {"iss":"enablebanking.com","aud":"api.enablebanking.com",
 *               "iat":<now>,"exp":<now+3600>}
 *   Implémenté en pur Java/Android, sans lib externe.
 *
 * ── Interface identique à GoCardlessManager ───────────────────────────────
 *   BankImportPipeline et la logique de règles (catégories, charges fixes,
 *   doublons) sont inchangés. Seule BankConnectionView est mise à jour.
 */
public class EnableBankingManager {

    public static final String BASE_URL     = "https://api.enablebanking.com/";
    public static final String REDIRECT_URI = "couplefinance://bank-callback";

    private static final String PREFS_NAME         = "enablebanking_prefs";
    private static final String KEY_APP_ID          = "eb_application_id";
    private static final String KEY_PRIVATE_KEY     = "eb_private_key_pem";
    private static final String KEY_SESSION_ID      = "eb_session_id";
    private static final String KEY_ACCOUNT_UIDS    = "eb_account_uids";
    private static final String KEY_LAST_STATE      = "eb_last_state";

    private static EnableBankingManager instance;

    private final Executor executor = Executors.newFixedThreadPool(2);
    private final Handler  handler  = new Handler(Looper.getMainLooper());

    private Context context;

    // ─────────────────────────────────────────────────────────────
    // Modèles publics (identiques à GoCardlessManager)
    // ─────────────────────────────────────────────────────────────

    public static class Institution {
        public final String id;       // name utilisé pour POST /auth
        public final String name;
        public final String logo;
        public final String bic;
        public final String country;

        public Institution(String id, String name, String logo, String bic, String country) {
            this.id      = id;
            this.name    = name;
            this.logo    = logo    != null ? logo    : "";
            this.bic     = bic     != null ? bic     : "";
            this.country = country != null ? country : "";
        }

        @Override public String toString() { return name; }
    }

    public static class BankTransaction {
        public String  id;
        public String  label;
        public double  amount;
        public String  currency;
        public long    dateMs;
        public String  bookingDate;
        public String  accountId;
        public boolean pending;

        public BankTransaction() {}
    }

    public interface Callback {
        void onSuccess(String result);
        void onError(String error);
    }

    public interface InstitutionsCallback {
        void onResult(List<Institution> list);
        void onError(String error);
    }

    public interface TransactionsCallback {
        void onResult(List<BankTransaction> transactions);
        void onError(String error);
    }

    // ─────────────────────────────────────────────────────────────
    // Singleton
    // ─────────────────────────────────────────────────────────────

    private EnableBankingManager() {}

    public static EnableBankingManager getInstance() {
        if (instance == null) instance = new EnableBankingManager();
        return instance;
    }

    public void init(Context ctx) {
        if (ctx != null) context = ctx.getApplicationContext();
    }

    // ─────────────────────────────────────────────────────────────
    // Configuration
    // ─────────────────────────────────────────────────────────────

    public void configure(String applicationId, String privateKeyPem) {
        prefs().edit()
                .putString(KEY_APP_ID,      applicationId)
                .putString(KEY_PRIVATE_KEY, privateKeyPem)
                .apply();
    }

    public boolean isConfigured() {
        String id  = prefs().getString(KEY_APP_ID,      "");
        String key = prefs().getString(KEY_PRIVATE_KEY, "");
        return !id.isEmpty() && !key.isEmpty();
    }

    public boolean isConnected() {
        String uids = prefs().getString(KEY_ACCOUNT_UIDS, "");
        return isConfigured() && !uids.isEmpty();
    }

    public List<String> getSavedAccountIds() {
        String raw = prefs().getString(KEY_ACCOUNT_UIDS, "");
        List<String> list = new ArrayList<>();
        if (raw.isEmpty()) return list;
        for (String uid : raw.split(",")) {
            String clean = uid.trim();
            if (!clean.isEmpty()) list.add(clean);
        }
        return list;
    }

    public String getSavedRequisitionId() {
        return prefs().getString(KEY_SESSION_ID, "");
    }

    public void clearConnection() {
        prefs().edit()
                .remove(KEY_SESSION_ID)
                .remove(KEY_ACCOUNT_UIDS)
                .remove(KEY_LAST_STATE)
                .apply();
    }

    public void clearAll() {
        prefs().edit().clear().apply();
    }

    // ─────────────────────────────────────────────────────────────
    // Institutions (liste des banques)
    // ─────────────────────────────────────────────────────────────

    /**
     * Récupère la liste des banques disponibles pour un pays.
     *
     * @param country Code ISO 3166-1 alpha-2, ex : "FR"
     */
    public void getInstitutions(String country, InstitutionsCallback cb) {
        if (!isConfigured()) {
            handler.post(() -> cb.onError("Enable Banking non configuré. Saisir l'Application ID et la clé privée."));
            return;
        }

        executor.execute(() -> {
            try {
                String jwt = buildJwt();
                String endpoint = "aspsps?country=" + country;
                JSONObject res  = getJson(endpoint, jwt);

                JSONArray aspsps = res.optJSONArray("aspsps");
                if (aspsps == null) {
                    handler.post(() -> cb.onResult(new ArrayList<>()));
                    return;
                }

                List<Institution> result = new ArrayList<>();
                for (int i = 0; i < aspsps.length(); i++) {
                    JSONObject obj  = aspsps.optJSONObject(i);
                    if (obj == null) continue;
                    String name    = obj.optString("name",    "");
                    String c       = obj.optString("country", country);
                    String logo    = obj.optString("logo",    "");
                    String bic     = obj.optString("bic",     "");
                    if (!name.isEmpty()) {
                        result.add(new Institution(name, name, logo, bic, c));
                    }
                }

                result.sort((a, b) -> a.name.compareToIgnoreCase(b.name));
                handler.post(() -> cb.onResult(result));

            } catch (Exception e) {
                handler.post(() -> cb.onError("Chargement des banques échoué : " + e.getMessage()));
            }
        });
    }

    // ─────────────────────────────────────────────────────────────
    // Autorisation (équivalent de createRequisition)
    // ─────────────────────────────────────────────────────────────

    /**
     * Démarre le flux d'autorisation pour une banque.
     * Retourne l'URL OAuth à ouvrir dans la WebView.
     *
     * @param institutionId Nom de la banque, ex : "BNP Paribas"
     * @param cb onSuccess(oauthUrl) — URL à ouvrir dans WebView
     */
    public void createRequisition(String institutionId, Callback cb) {
        if (!isConfigured()) {
            handler.post(() -> cb.onError("Enable Banking non configuré."));
            return;
        }

        executor.execute(() -> {
            try {
                String jwt   = buildJwt();
                String state = "cf_" + System.currentTimeMillis();

                // Calculer valid_until = maintenant + 90 jours
                Calendar cal = Calendar.getInstance();
                cal.add(Calendar.DAY_OF_YEAR, 90);
                String validUntil = String.format(java.util.Locale.US,
                        "%04d-%02d-%02dT00:00:00.000Z",
                        cal.get(Calendar.YEAR),
                        cal.get(Calendar.MONTH) + 1,
                        cal.get(Calendar.DAY_OF_MONTH));

                String body = "{"
                        + "\"access\":{\"valid_until\":\"" + validUntil + "\"},"
                        + "\"aspsp\":{\"name\":\"" + esc(institutionId) + "\",\"country\":\"FR\"},"
                        + "\"state\":\"" + esc(state) + "\","
                        + "\"redirect_url\":\"" + REDIRECT_URI + "\","
                        + "\"psu_type\":\"personal\""
                        + "}";

                JSONObject res   = postJson("auth", jwt, body);
				android.util.Log.e("ENABLE_BANKING_AUTH_REQUEST", body);
android.util.Log.e("ENABLE_BANKING_AUTH_RESPONSE", res.toString(2));
                String oauthUrl  = res.optString("url", "");

                if (oauthUrl.isEmpty()) {
                    handler.post(() -> cb.onError("URL d'autorisation manquante dans la réponse."));
                    return;
                }

                // Sauvegarder le state pour validation au retour
                prefs().edit().putString(KEY_LAST_STATE, state).apply();

                handler.post(() -> cb.onSuccess(oauthUrl));

            } catch (Exception e) {
                handler.post(() -> cb.onError("Démarrage de l'autorisation échoué : " + e.getMessage()));
            }
        });
    }

    // ─────────────────────────────────────────────────────────────
    // Finalisation de la session (équivalent de fetchAccounts)
    // ─────────────────────────────────────────────────────────────

    /**
     * Finalise l'autorisation après le retour de la WebView.
     * Échange le code OAuth contre un session_id + liste de comptes.
     *
     * @param callbackUrl URL complète reçue dans le callback WebView.
     *                    Format : couplefinance://bank-callback?code=XXX&state=YYY
     * @param cb onSuccess(account_uids_csv)
     */
    public void fetchAccounts(String callbackUrl, Callback cb) {
		android.util.Log.e("ENABLE_BANKING_CALLBACK_URL", callbackUrl);
        executor.execute(() -> {
            try {
                String code  = extractParam(callbackUrl, "code");
                String state = extractParam(callbackUrl, "state");
                String error = extractParam(callbackUrl, "error");

                if (!error.isEmpty()) {
                    String desc = extractParam(callbackUrl, "error_description");
                    handler.post(() -> cb.onError("Autorisation refusée : "
                            + (desc.isEmpty() ? error : desc)));
                    return;
                }

                if (code.isEmpty()) {
                    handler.post(() -> cb.onError("Code OAuth absent dans l'URL de retour."));
                    return;
                }

                String jwt  = buildJwt();
                String body = "{\"code\":\"" + esc(code) + "\","
                            + "\"state\":\"" + esc(state) + "\"}";

                JSONObject res     = postJson("sessions", jwt, body);
				android.util.Log.e("ENABLE_BANKING_SESSION_REQUEST", body);
android.util.Log.e("ENABLE_BANKING_SESSION_RESPONSE", res.toString(2));
android.util.Log.e("ENABLE_BANKING_SESSION_ID", session);
                String     session = res.optString("session_id", "");
                JSONArray  accounts = res.optJSONArray("accounts");

                if (session.isEmpty()) {
                    handler.post(() -> cb.onError("Session introuvable dans la réponse."));
                    return;
                }

                if (accounts == null || accounts.length() == 0) {
                    handler.post(() -> cb.onError("Aucun compte retourné. Vérifier que vous avez bien lié vos comptes sur enablebanking.com"));
                    return;
                }

                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < accounts.length(); i++) {
                    JSONObject acc = accounts.optJSONObject(i);
                    if (acc == null) continue;
                    String uid = acc.optString("uid", "");
                    if (!uid.isEmpty()) {
                        if (sb.length() > 0) sb.append(",");
                        sb.append(uid);
                    }
					android.util.Log.e("ENABLE_BANKING_ACCOUNT_OBJECT",
        acc.toString(2));

android.util.Log.e("ENABLE_BANKING_ACCOUNT_UID",
        uid);
                }

                String uidsCsv = sb.toString();
                prefs().edit()
                        .putString(KEY_SESSION_ID,   session)
                        .putString(KEY_ACCOUNT_UIDS, uidsCsv)
                        .apply();

                handler.post(() -> cb.onSuccess(uidsCsv));

            } catch (Exception e) {
                handler.post(() -> cb.onError("Récupération des comptes échouée : " + e.getMessage()));
            }
			android.util.Log.e("ENABLE_BANKING_CODE", code);
android.util.Log.e("ENABLE_BANKING_STATE", state);
android.util.Log.e("ENABLE_BANKING_ERROR", error);
        });
    }

    // ─────────────────────────────────────────────────────────────
    // Transactions
    // ─────────────────────────────────────────────────────────────

    /**
     * Récupère les transactions d'un compte sur une période.
     *
     * @param accountUid  UID du compte Enable Banking
     * @param dateFrom    "YYYY-MM-DD"
     * @param dateTo      "YYYY-MM-DD"
     */
    public void getTransactions(String accountUid, String dateFrom, String dateTo,
                                TransactionsCallback cb) {
        executor.execute(() -> {
            try {
                String jwt      = buildJwt();
                String endpoint = "accounts/" + accountUid + "/transactions"
                        + "?date_from=" + dateFrom
                        + "&date_to="   + dateTo;

                JSONObject res   = getJson(endpoint, jwt);
                JSONObject txObj = res.optJSONObject("transactions");

                if (txObj == null) {
                    handler.post(() -> cb.onResult(new ArrayList<>()));
                    return;
                }

                List<BankTransaction> result = new ArrayList<>();
                result.addAll(parseTxArray(txObj.optJSONArray("booked"),  accountUid, false));
                result.addAll(parseTxArray(txObj.optJSONArray("pending"), accountUid, true));

                handler.post(() -> cb.onResult(result));

            } catch (Exception e) {
                handler.post(() -> cb.onError("Récupération transactions échouée : " + e.getMessage()));
            }
        });
    }

    /**
     * Récupère les transactions de TOUS les comptes connectés.
     */
    public void syncAllAccounts(String dateFrom, String dateTo, TransactionsCallback cb) {
        List<String> uids = getSavedAccountIds();
        if (uids.isEmpty()) {
            handler.post(() -> cb.onError("Aucun compte connecté. Veuillez d'abord connecter votre banque."));
            return;
        }

        executor.execute(() -> {
            List<BankTransaction> all       = new ArrayList<>();
            String                lastError = null;

            try {
                String jwt = buildJwt();

                for (String uid : uids) {
                    try {
                        String endpoint = "accounts/" + uid + "/transactions"
                                + "?date_from=" + dateFrom
                                + "&date_to="   + dateTo;

                        JSONObject res   = getJson(endpoint, jwt);
                        JSONObject txObj = res.optJSONObject("transactions");

                        if (txObj != null) {
                            all.addAll(parseTxArray(txObj.optJSONArray("booked"),  uid, false));
                            all.addAll(parseTxArray(txObj.optJSONArray("pending"), uid, true));
                        }
                    } catch (Exception e) {
                        lastError = e.getMessage();
                    }
                }

            } catch (Exception e) {
                lastError = e.getMessage();
            }

            final List<BankTransaction> finalAll   = all;
            final String               finalError = lastError;

            handler.post(() -> {
                if (finalAll.isEmpty() && finalError != null) {
                    cb.onError("Synchronisation échouée : " + finalError);
                } else {
                    cb.onResult(finalAll);
                }
            });
        });
    }

    // ─────────────────────────────────────────────────────────────
    // Parsing des transactions Enable Banking
    // ─────────────────────────────────────────────────────────────

    private List<BankTransaction> parseTxArray(JSONArray arr, String accountUid, boolean pending) {
        List<BankTransaction> list = new ArrayList<>();
        if (arr == null) return list;

        for (int i = 0; i < arr.length(); i++) {
            JSONObject obj = arr.optJSONObject(i);
            if (obj == null) continue;

            BankTransaction bt = new BankTransaction();
            bt.accountId = accountUid;
            bt.pending   = pending;

            // ID de la transaction
            bt.id = obj.optString("transaction_id",
                    obj.optString("entry_reference", ""));

            // Montant (Enable Banking snake_case)
            JSONObject amtObj = obj.optJSONObject("transaction_amount");
            if (amtObj != null) {
                String amtStr = amtObj.optString("amount", "0");
                bt.currency = amtObj.optString("currency", "EUR");
                try {
                    double raw = Double.parseDouble(amtStr.replace(",", "."));
                    // Enable Banking utilise credit_debit_indicator: DBIT = débit, CRDT = crédit
                    String cdi = obj.optString("credit_debit_indicator", "");
                    if ("DBIT".equals(cdi)) raw = -Math.abs(raw);
                    else if ("CRDT".equals(cdi)) raw = Math.abs(raw);
                    bt.amount = raw;
                } catch (Exception ignored) { bt.amount = 0; }
            }

            // Date
            String dateStr   = obj.optString("booking_date", obj.optString("value_date", ""));
            bt.bookingDate   = dateStr;
            bt.dateMs        = parseDateToMillis(dateStr);

            // Libellé (priorité : remittance → creditor → debtor)
            String info = obj.optString("remittance_information_unstructured", "");
            if (info.isEmpty()) {
                JSONObject creditor = obj.optJSONObject("creditor");
                if (creditor != null) info = creditor.optString("name", "");
            }
            if (info.isEmpty()) {
                JSONObject debtor = obj.optJSONObject("debtor");
                if (debtor != null) info = debtor.optString("name", "");
            }
            if (info.isEmpty()) info = "Transaction " + dateStr;
            bt.label = cleanLabel(info);

            if (Math.abs(bt.amount) > 0.001) list.add(bt);
        }

        return list;
    }

    // ─────────────────────────────────────────────────────────────
    // JWT RS256 — pur Java/Android, sans lib externe
    // ─────────────────────────────────────────────────────────────

    /**
     * Construit un JWT RS256 valide pour Enable Banking.
     *
     * Header : {"alg":"RS256","kid":"<applicationId>"}
     * Payload: {"iss":"enablebanking.com","aud":"api.enablebanking.com",
     *           "iat":<now>,"exp":<now+3600>}
     *
     * Signé avec la clé RSA privée PKCS#8 PEM stockée en SharedPreferences.
     */
    private String buildJwt() throws Exception {
        String applicationId = prefs().getString(KEY_APP_ID,      "");
        String privateKeyPem = prefs().getString(KEY_PRIVATE_KEY, "");

        if (applicationId.isEmpty() || privateKeyPem.isEmpty()) {
            throw new Exception("Enable Banking non configuré (Application ID ou clé manquante).");
        }

        // 1. Header
        String headerJson = "{\"alg\":\"RS256\",\"kid\":\"" + esc(applicationId) + "\"}";
        String headerB64  = base64url(headerJson.getBytes("UTF-8"));

        // 2. Payload
        long   iat         = System.currentTimeMillis() / 1000L;
        long   exp         = iat + 3600L;
        String payloadJson = "{\"iss\":\"enablebanking.com\","
                + "\"aud\":\"api.enablebanking.com\","
                + "\"iat\":" + iat + ","
                + "\"exp\":" + exp + "}";
        String payloadB64  = base64url(payloadJson.getBytes("UTF-8"));

        // 3. Signing input
        String signingInput = headerB64 + "." + payloadB64;

        // 4. Charger la clé privée RSA (PKCS#8 PEM)
        PrivateKey privateKey = loadPrivateKey(privateKeyPem);

        // 5. Signer avec SHA256withRSA
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(signingInput.getBytes("UTF-8"));
        byte[] signatureBytes = signer.sign();

        // 6. Encoder en Base64URL
        String signatureB64 = base64url(signatureBytes);

        return signingInput + "." + signatureB64;
    }

    /**
     * Charge une clé privée RSA depuis un PEM PKCS#8.
     * Format attendu : fichier téléchargé depuis le portail Enable Banking.
     */
    private PrivateKey loadPrivateKey(String pem) throws Exception {
        // Nettoyer les headers PEM et les espaces
        String base64Key = pem
                .replace("-----BEGIN PRIVATE KEY-----",     "")
                .replace("-----END PRIVATE KEY-----",       "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----",   "")
                .replaceAll("[\\r\\n\\s]", "");

        byte[] keyBytes = Base64.decode(base64Key, Base64.DEFAULT);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    /** Encode des bytes en Base64URL (sans padding, URL-safe). */
    private static String base64url(byte[] data) {
        return Base64.encodeToString(data,
                Base64.NO_PADDING | Base64.NO_WRAP | Base64.URL_SAFE);
    }

    // ─────────────────────────────────────────────────────────────
    // HTTP helpers
    // ─────────────────────────────────────────────────────────────

    private JSONObject getJson(String endpoint, String jwt) throws Exception {
        HttpURLConnection conn = openConn(BASE_URL + endpoint, "GET", jwt, false);
        int    code = conn.getResponseCode();
        String body = safeRead(code < 400 ? conn.getInputStream() : conn.getErrorStream());

        if (code == 401) throw new Exception("Authentification invalide. Vérifiez l'Application ID et la clé privée.");
        if (code < 200 || code >= 300) throw new Exception("HTTP " + code + " : " + body);
        return new JSONObject(body);
    }

    private JSONObject postJson(String endpoint, String jwt, String bodyStr) throws Exception {
        HttpURLConnection conn = openConn(BASE_URL + endpoint, "POST", jwt, true);
        DataOutputStream dos = new DataOutputStream(conn.getOutputStream());
        dos.write(bodyStr.getBytes("UTF-8"));
        dos.flush(); dos.close();

        int    code = conn.getResponseCode();
        String body = safeRead(code < 400 ? conn.getInputStream() : conn.getErrorStream());

        if (code == 401) throw new Exception("Authentification invalide. Vérifiez l'Application ID et la clé privée.");
        if (code < 200 || code >= 300) throw new Exception("HTTP " + code + " : " + body);
        return new JSONObject(body);
    }

    private HttpURLConnection openConn(String urlStr, String method,
                                        String jwt, boolean output) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setRequestMethod(method);
        conn.setRequestProperty("Accept",        "application/json");
        conn.setRequestProperty("Content-Type",  "application/json");
        if (jwt != null && !jwt.isEmpty()) {
            conn.setRequestProperty("Authorization", "Bearer " + jwt);
        }
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(15000);
        conn.setDoOutput(output);
        return conn;
    }

    // ─────────────────────────────────────────────────────────────
    // Utilitaires
    // ─────────────────────────────────────────────────────────────

    /** Parse "YYYY-MM-DD" → timestamp millis. */
    public static long parseDateToMillis(String dateStr) {
        if (dateStr == null || dateStr.length() < 10) return System.currentTimeMillis();
        try {
            int year  = Integer.parseInt(dateStr.substring(0, 4));
            int month = Integer.parseInt(dateStr.substring(5, 7)) - 1;
            int day   = Integer.parseInt(dateStr.substring(8, 10));
            java.util.Calendar c = java.util.Calendar.getInstance();
            c.set(year, month, day, 12, 0, 0);
            c.set(java.util.Calendar.MILLISECOND, 0);
            return c.getTimeInMillis();
        } catch (Exception e) {
            return System.currentTimeMillis();
        }
    }

    /** Timestamp millis → "YYYY-MM-DD". */
    public static String millisToDateStr(long millis) {
        java.util.Calendar c = java.util.Calendar.getInstance();
        c.setTimeInMillis(millis);
        return String.format(java.util.Locale.US, "%04d-%02d-%02d",
                c.get(java.util.Calendar.YEAR),
                c.get(java.util.Calendar.MONTH) + 1,
                c.get(java.util.Calendar.DAY_OF_MONTH));
    }

    private String cleanLabel(String raw) {
        if (raw == null || raw.trim().isEmpty()) return "Transaction";
        String s = raw.trim();
        s = s.replaceAll("(?i)SEPA\\s+\\w+\\s+TRANSFER\\s*", "");
        s = s.replaceAll("(?i)VIREMENT\\s+SEPA\\s*", "");
        s = s.replaceAll("\\s+", " ").trim();
        return s.isEmpty() ? raw.trim() : s;
    }

    private String extractParam(String url, String param) {
        try {
            int idx = url.indexOf(param + "=");
            if (idx < 0) return "";
            int start = idx + param.length() + 1;
            int end   = url.indexOf("&", start);
            String val = end < 0 ? url.substring(start) : url.substring(start, end);
            return java.net.URLDecoder.decode(val, "UTF-8");
        } catch (Exception e) { return ""; }
    }

    private String esc(String v) {
        if (v == null) return "";
        return v.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String safeRead(InputStream is) {
        if (is == null) return "";
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder  sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        } catch (Exception e) { return ""; }
    }

    private SharedPreferences prefs() {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }
}
