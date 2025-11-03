// api/submit-review.js (Vercel Serverless Function)

const { createClient } = require('@supabase/supabase-js'); 
// Vercel utilise le même mécanisme de process.env que Netlify

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const PROXY_SECRET_KEY = process.env.PROXY_SECRET_KEY; // Clé de sécurité

const serviceClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Format de fonction Vercel (plus standard)
export default async (req, res) => {
    
    // Le corps de la requête est déjà parsé par Vercel
    const clientSecret = req.headers['x-proxy-secret'];

    // 1. Vérification de la méthode
    if (req.method !== 'POST') {
        return res.status(405).send('Méthode non autorisée.');
    }
    
    // 2. Vérification de la clé secrète du Proxy Velo
    if (clientSecret !== PROXY_SECRET_KEY) {
        return res.status(403).send('Accès interdit. Clé secrète invalide.');
    }

    let avisData, userToken;

    try {
        const body = req.body; // Vercel parse automatiquement
        avisData = body.avisData;
        userToken = body.userToken;
    } catch (e) {
        return res.status(400).send({ error: "Format JSON de requête invalide." });
    }

    if (!userToken) {
        return res.status(400).send({ error: "Jeton utilisateur manquant." });
    }

    try {
        // 3. VÉRIFICATION SÉCURISÉE DU JETON
        const { error: authError } = await serviceClient.auth.getUser(userToken);

        if (authError) {
            return res.status(401).send({ error: "Jeton invalide. Reconnexion nécessaire." });
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
            // Erreur RLS
            return res.status(500).send({ error: "Erreur d'insertion Supabase (RLS?): " + error.message });
        }

        // Succès : Réponse JSON standard
        return res.status(200).send({ success: true, data: data });

    } catch (err) {
        return res.status(500).send({ error: "Erreur interne de la fonction Vercel: " + err.message });
    }
};
