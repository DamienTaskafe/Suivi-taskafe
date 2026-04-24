// TASKAFE — IndexedDB offline layer
// Provides local cache for clients/sales/stocks and a pending operations queue.

const DB_NAME = 'taskafe-offline';
const DB_VERSION = 2;

let _db = null;

function openDB() {
  return new Promise((resolve, reject) => {
    if (_db) { resolve(_db); return; }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('clients'))
        db.createObjectStore('clients', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('sales'))
        db.createObjectStore('sales', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('stocks'))
        db.createObjectStore('stocks', { keyPath: 'category' });
      // commercial_stocks stores the current user's per-category commercial stock
      // keyed by category (same shape as the 'stocks' store for easy reuse).
      if (!db.objectStoreNames.contains('commercial_stocks'))
        db.createObjectStore('commercial_stocks', { keyPath: 'category' });
      if (!db.objectStoreNames.contains('pendingOps')) {
        const opStore = db.createObjectStore('pendingOps', { keyPath: 'id', autoIncrement: true });
        opStore.createIndex('by_timestamp', 'timestamp');
      }
    };
    req.onsuccess = e => { _db = e.target.result; resolve(_db); };
    req.onerror = e => reject(e.target.error);
  });
}

export async function initOfflineDB() {
  await openDB();
}

/** Replace all records in a store with the given array. */
export async function saveRecords(storeName, records) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    store.clear();
    records.forEach(r => store.put(r));
    tx.oncomplete = () => resolve();
    tx.onerror = e => reject(e.target.error);
  });
}

/** Load all records from a store. */
export async function loadRecords(storeName) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = e => reject(e.target.error);
  });
}

/** Upsert a single record in a store. */
export async function putRecord(storeName, record) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = e => reject(e.target.error);
  });
}

/** Delete a single record by key. */
export async function deleteRecord(storeName, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = e => reject(e.target.error);
  });
}

/** Enqueue an offline operation. Returns the assigned id. */
export async function addPendingOp(op) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pendingOps', 'readwrite');
    const req = tx.objectStore('pendingOps').add({ ...op, timestamp: Date.now() });
    req.onsuccess = () => resolve(req.result);
    req.onerror = e => reject(e.target.error);
  });
}

/** Return all pending ops sorted by timestamp ascending. */
export async function getPendingOps() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pendingOps', 'readonly');
    const req = tx.objectStore('pendingOps').getAll();
    req.onsuccess = () => resolve((req.result || []).sort((a, b) => a.timestamp - b.timestamp));
    req.onerror = e => reject(e.target.error);
  });
}

/** Remove a pending op by its autoincrement id. */
export async function removePendingOp(id) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pendingOps', 'readwrite');
    tx.objectStore('pendingOps').delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = e => reject(e.target.error);
  });
}

/** Update (upsert) a pending op record in-place (uses its existing id key). */
export async function updatePendingOp(op) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pendingOps', 'readwrite');
    tx.objectStore('pendingOps').put(op);
    tx.oncomplete = () => resolve();
    tx.onerror = e => reject(e.target.error);
  });
}

/** Count pending ops. */
export async function countPendingOps() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('pendingOps', 'readonly');
    const req = tx.objectStore('pendingOps').count();
    req.onsuccess = () => resolve(req.result);
    req.onerror = e => reject(e.target.error);
  });
}
