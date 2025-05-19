require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto'); // Pour la vérification de signature

const app = express();

// ======================
// CONFIGURATION MIDDLEWARE
// ======================
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.urlencoded({ extended: true }));

// ======================
// ROUTES PRINCIPALES
// ======================

// Route de validation webhook (GET)
app.get('/webhook', (req, res) => {
  console.log('[WEBHOOK_GET] Validation en cours...');
  
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token) {
    if (mode === 'subscribe' && token === process.env.WHATSAPP_WEBHOOK_TOKEN) {
      console.log('[WEBHOOK_GET] Validation réussie');
      return res.status(200).send(challenge);
    }
  }
  
  console.error('[WEBHOOK_GET] Échec de validation');
  res.sendStatus(403);
});

// Route de réception des messages (POST)
app.post('/webhook', (req, res) => {
  console.log('[WEBHOOK_POST] Message reçu');
  
  try {
    const entry = req.body.entry?.[0];
    const changes = entry?.changes?.[0];
    const value = changes?.value;
    
    if (value?.messages) {
      value.messages.forEach(processIncomingMessage);
    }

    res.sendStatus(200);
  } catch (error) {
    console.error('[WEBHOOK_POST] Erreur:', error);
    res.sendStatus(500);
  }
});

// ======================
// FONCTIONS UTILITAIRES
// ======================

function verifyRequestSignature(req, res, buf) {
  const signature = req.headers['x-hub-signature-256'];
  
  if (!signature) {
    console.warn('[SECURITY] Signature manquante');
    throw new Error('Signature non fournie');
  }

  const expectedSignature = crypto
    .createHmac('sha256', process.env.WHATSAPP_WEBHOOK_TOKEN)
    .update(buf)
    .digest('hex');

  if (`sha256=${expectedSignature}` !== signature) {
    console.error('[SECURITY] Signature invalide');
    throw new Error('Signature invalide');
  }
}

function processIncomingMessage(message) {
  console.log('[MESSAGE] Nouveau message:', {
    from: message.from,
    type: message.type,
    timestamp: message.timestamp
  });
  
  // Ajoutez ici votre logique de traitement
}

// ======================
// DÉMARRAGE DU SERVEUR
// ======================
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SERVER] En écoute sur le port ${PORT}`);
});

// ======================
// GESTION DES SIGNEAUX
// ======================
['SIGINT', 'SIGTERM'].forEach(signal => {
  process.on(signal, () => {
    console.log(`\n[${signal}] Arrêt propre du serveur...`);
    
    server.close(() => {
      console.log('[SERVER] Toutes connexions fermées');
      process.exit(0);
    });

    // Arrêt forcé après 5 secondes
    setTimeout(() => {
      console.error('[SERVER] Arrêt forcé!');
      process.exit(1);
    }, 5000);
  });
});
