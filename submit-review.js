// netlify/functions/submit-review.js

// Importation standard de la librairie Supabase (stable en Node.js)
const { createClient } = require('@supabase/supabase-js'); 

// Récupération des clés via les variables d'environnement Netlify
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const PROXY_SECRET_KEY = process.env.PROXY_SECRET_KEY; // Clé de sécurité

// Création du client service_role (nécessaire pour la vérification sécurisée du jeton)
const serviceClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);


exports.handler = async (event, context) => {
    // 1. Vérification de la méthode
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: 'Méthode non autorisée.' };
    }
    
    // 2. Vérification de la clé secrète du Proxy Velo
    const clientSecret = event.headers['x-proxy-secret'];
    if (clientSecret !== PROXY_SECRET_KEY) {
        return { statusCode: 403, body: 'Accès interdit. Clé secrète invalide.' };
    }

    let avisData, userToken;

    try {
        const body = JSON.parse(event.body);
        avisData = body.avisData;
        userToken = body.userToken;
    } catch (e) {
        return { statusCode: 400, body: JSON.stringify({ error: "Format JSON de requête invalide." }) };
    }

    // Le jeton utilisateur doit être présent
    if (!userToken) {
        return { statusCode: 400, body: JSON.stringify({ error: "Jeton utilisateur manquant." }) };
    }

    try {
        // 3. VÉRIFICATION SÉCURISÉE DU JETON (stable ici)
        const { data: userData, error: authError } = await serviceClient.auth.getUser(userToken);

        if (authError || !userData.user) {
            return { statusCode: 401, body: JSON.stringify({ error: "Jeton invalide. Reconnexion nécessaire." }) };
        }
        
        // 4. CRÉATION DU CLIENT AUTHENTIFIÉ pour l'insertion RLS
        const userClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
            global: {
                headers: {
                    'Authorization': `Bearer ${userToken}`,
                }
            }
        });

        // 5. INSERTION DES DONNÉES
        const { data, error } = await userClient.from('avis')
            .insert([
                {
                    provider_id: avisData.provider_id,
                    prix: avisData.prix,
                    service: avisData.service,
                    fiabilite: avisData.fiabilite,
                    ecologie: avisData.ecologie,
                    engagement: avisData.engagement,
                    comment: avisData.comment,
                }
            ])
            .select();

        if (error) {
            // Retourne l'erreur RLS ou de données clairement à Velo
            return { statusCode: 500, body: JSON.stringify({ error: "Erreur d'insertion Supabase (RLS?): " + error.message }) };
        }

        // Succès
        return { statusCode: 200, body: JSON.stringify({ success: true, data: data }) };

    } catch (err) {
        return { statusCode: 500, body: JSON.stringify({ error: "Erreur interne de la fonction Netlify: " + err.message }) };
    }
};
