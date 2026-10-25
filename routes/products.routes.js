const express = require('express');
const router = express.Router();
const businessDb = require('../db/business');
const auditDb = require('../db/audit');
const { calculateDiff } = require('../utils/diff');
const verifyJWT = require('../middleware/verifyJWT');
const requireRole = require('../middleware/requireRole');

router.use(verifyJWT);

/**
 * GET /api/products
 * Read products catalog (Admin, Auditor, User)
 */
router.get('/', (req, res) => {
  const products = businessDb.getProducts();
  return res.json({ products });
});

/**
 * GET /api/products/:id
 */
router.get('/:id', (req, res) => {
  const product = businessDb.getProductById(req.params.id);
  if (!product) {
    return res.status(404).json({ error: 'Product not found' });
  }
  return res.json({ product });
});

/**
 * POST /api/products
 * Create product (Admin only - Auditor has read-only access)
 */
router.post('/', requireRole('admin'), (req, res) => {
  const { name, sku, category, price, stock, description } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  if (!name || !sku || !category || price === undefined || stock === undefined) {
    return res.status(400).json({ error: 'Missing required product fields (name, sku, category, price, stock)' });
  }

  const newProduct = businessDb.createProduct({
    name,
    sku,
    category,
    price,
    stock,
    description,
    created_by: req.user.username
  });

  // Forensic Audit Log
  auditDb.logAudit({
    event: 'CREATE_PRODUCT',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `Created product '${newProduct.name}' (SKU: ${newProduct.sku}, Price: $${newProduct.price})`,
    entity_type: 'product',
    entity_id: newProduct.id,
    before_snapshot: null,
    after_snapshot: newProduct,
    diff: { created: newProduct },
    jti: req.user.jti,
    status: 'SUCCESS'
  });

  return res.status(201).json({ product: newProduct });
});

/**
 * PUT /api/products/:id
 * Update product (Admin only)
 */
router.put('/:id', requireRole('admin'), (req, res) => {
  const { id } = req.params;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  const beforeProduct = businessDb.getProductById(id);
  if (!beforeProduct) {
    return res.status(404).json({ error: 'Product not found' });
  }

  const updatedProduct = businessDb.updateProduct(id, req.body);
  const { changedFields, diff } = calculateDiff(beforeProduct, updatedProduct);

  // Forensic Audit Log with Yellow-highlight before/after diff
  auditDb.logAudit({
    event: 'UPDATE_PRODUCT',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `Updated product '${updatedProduct.name}' (${changedFields.join(', ')})`,
    entity_type: 'product',
    entity_id: updatedProduct.id,
    before_snapshot: beforeProduct,
    after_snapshot: updatedProduct,
    diff: diff,
    jti: req.user.jti,
    status: 'SUCCESS'
  });

  return res.json({ product: updatedProduct, diff });
});

/**
 * DELETE /api/products/:id
 * Delete product (Admin only)
 */
router.delete('/:id', requireRole('admin'), (req, res) => {
  const { id } = req.params;
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown-Client';

  const beforeProduct = businessDb.getProductById(id);
  if (!beforeProduct) {
    return res.status(404).json({ error: 'Product not found' });
  }

  const deleted = businessDb.deleteProduct(id);

  // Forensic Audit Log
  auditDb.logAudit({
    event: 'DELETE_PRODUCT',
    user_id: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    ip_address: ip,
    user_agent: userAgent,
    action: `Deleted product '${deleted.name}' (SKU: ${deleted.sku})`,
    entity_type: 'product',
    entity_id: deleted.id,
    before_snapshot: deleted,
    after_snapshot: null,
    diff: { deleted: deleted.name },
    jti: req.user.jti,
    status: 'SUCCESS'
  });

  return res.json({ message: `Product '${deleted.name}' deleted successfully`, product: deleted });
});

module.exports = router;
