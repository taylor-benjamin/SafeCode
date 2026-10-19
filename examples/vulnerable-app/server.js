// INTENTIONALLY VULNERABLE demo server. Do not copy any of this code.
// Each block names the SAFECODE checklist rule it triggers.

const https = require("https");
const mysql = require("mysql");

const db = mysql.createConnection({ host: "localhost", user: "app" });

// SC-008: cleartext http:// URL for a remote service.
const WEBHOOK_URL = "http://hooks.partner-service.io/notify";

function getProduct(req, res) {
  // SC-003: SQL built with a template literal containing user input.
  db.query(`SELECT * FROM products WHERE id = ${req.query.id}`, (err, rows) => res.json(rows));
}

function search(req, res) {
  // SC-003: SQL built with string concatenation.
  db.query("SELECT * FROM products WHERE name LIKE '%" + req.query.q + "%'", (err, rows) => res.json(rows));
}

function applyDiscount(req) {
  // SC-003: eval on request data runs arbitrary JavaScript.
  return eval(req.body.formula);
}

// SC-008: TLS certificate verification disabled.
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

module.exports = { getProduct, search, applyDiscount, insecureAgent, WEBHOOK_URL };
