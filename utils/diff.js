/**
 * Utility to calculate JSON before/after snapshots diff
 */
function calculateDiff(beforeObj, afterObj, ignoredKeys = ['updated_at']) {
  if (!beforeObj && !afterObj) return { hasChanges: false, changedFields: [], diff: {} };
  
  const before = beforeObj || {};
  const after = afterObj || {};
  
  const allKeys = Array.from(new Set([...Object.keys(before), ...Object.keys(after)]));
  const diff = {};
  const changedFields = [];

  for (const key of allKeys) {
    if (ignoredKeys.includes(key)) continue;

    const valBefore = before[key];
    const valAfter = after[key];

    // Normalize types for comparison
    const strBefore = JSON.stringify(valBefore !== undefined ? valBefore : null);
    const strAfter = JSON.stringify(valAfter !== undefined ? valAfter : null);

    if (strBefore !== strAfter) {
      changedFields.push(key);
      diff[key] = {
        before: valBefore !== undefined ? valBefore : null,
        after: valAfter !== undefined ? valAfter : null
      };
    }
  }

  return {
    hasChanges: changedFields.length > 0,
    changedFields,
    diff
  };
}

module.exports = {
  calculateDiff
};
