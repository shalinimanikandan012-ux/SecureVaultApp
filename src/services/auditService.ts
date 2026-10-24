/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Audit & Digital Forensics Service
 * Tamper-Evident SHA-256 Cryptographic Hash Chain
 */

import { AuditLogEntry, HashChainVerificationResult } from '../types';
import { sha256Hex } from './crypto';

export const GENESIS_PREV_HASH =
  '0000000000000000000000000000000000000000000000000000000000000000';

const AUDIT_STORAGE_KEY = 'securevault_audit_chain_v1';

/**
 * Computes canonical SHA-256 hash for an audit log entry.
 * Binds: index + timestamp + actorId + action + resourceType + resourceId + status + details + prevHash
 */
export async function computeEntryHash(
  entry: Omit<AuditLogEntry, 'hash'>
): Promise<string> {
  const canonicalPayload = JSON.stringify({
    index: entry.index,
    timestamp: entry.timestamp,
    actorId: entry.actorId,
    actorEmail: entry.actorEmail,
    action: entry.action,
    resourceType: entry.resourceType,
    resourceId: entry.resourceId,
    status: entry.status,
    details: entry.details,
    prevHash: entry.prevHash,
  });

  return sha256Hex(canonicalPayload);
}

/**
 * Appends a new immutable audit record to the cryptographic hash chain.
 */
export async function recordAuditEvent(params: {
  actorId: string;
  actorEmail: string;
  action: string;
  resourceType: string;
  resourceId: string;
  status: 'SUCCESS' | 'FAILURE' | 'TAMPER_DETECTED';
  details: string;
}): Promise<AuditLogEntry> {
  const chain = getAuditLogEntries();
  const index = chain.length;
  const prevHash = index === 0 ? GENESIS_PREV_HASH : chain[index - 1].hash;

  const entryWithoutHash: Omit<AuditLogEntry, 'hash'> = {
    id: `audit-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
    index,
    timestamp: new Date().toISOString(),
    actorId: params.actorId,
    actorEmail: params.actorEmail,
    action: params.action,
    resourceType: params.resourceType,
    resourceId: params.resourceId,
    status: params.status,
    details: params.details,
    prevHash,
  };

  const hash = await computeEntryHash(entryWithoutHash);
  const entry: AuditLogEntry = { ...entryWithoutHash, hash };

  chain.push(entry);
  localStorage.setItem(AUDIT_STORAGE_KEY, JSON.stringify(chain));
  return entry;
}

/**
 * Retrieves all audit log entries from storage.
 */
export function getAuditLogEntries(): AuditLogEntry[] {
  try {
    const raw = localStorage.getItem(AUDIT_STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

/**
 * Recalculates and verifies the cryptographic hash chain from Genesis to tip.
 * Returns exact location and nature of any tamper attempt.
 */
export async function verifyAuditChainIntegrity(): Promise<HashChainVerificationResult> {
  const chain = getAuditLogEntries();
  const verifiedAt = new Date().toISOString();

  if (chain.length === 0) {
    return {
      isValid: true,
      totalChecked: 0,
      brokenAtIndex: null,
      reason: 'Audit log chain is empty.',
      verifiedAt,
    };
  }

  for (let i = 0; i < chain.length; i++) {
    const current = chain[i];

    // Check Index consistency
    if (current.index !== i) {
      return {
        isValid: false,
        totalChecked: i,
        brokenAtIndex: i,
        brokenEntryId: current.id,
        reason: `Index mismatch at position ${i}. Expected index ${i}, found ${current.index}.`,
        verifiedAt,
      };
    }

    // Check prevHash binding
    const expectedPrev = i === 0 ? GENESIS_PREV_HASH : chain[i - 1].hash;
    if (current.prevHash !== expectedPrev) {
      return {
        isValid: false,
        totalChecked: i,
        brokenAtIndex: i,
        brokenEntryId: current.id,
        expectedHash: expectedPrev,
        actualHash: current.prevHash,
        reason: `Chain linkage severed at block #${i}. Stored prevHash does not match previous block hash.`,
        verifiedAt,
      };
    }

    // Check block payload integrity hash
    const calculatedHash = await computeEntryHash(current);
    if (calculatedHash !== current.hash) {
      return {
        isValid: false,
        totalChecked: i,
        brokenAtIndex: i,
        brokenEntryId: current.id,
        expectedHash: calculatedHash,
        actualHash: current.hash,
        reason: `Cryptographic payload hash mismatch at block #${i}. Block data has been modified.`,
        verifiedAt,
      };
    }
  }

  return {
    isValid: true,
    totalChecked: chain.length,
    brokenAtIndex: null,
    reason: `All ${chain.length} audit entries verified. Cryptographic hash chain is intact.`,
    verifiedAt,
  };
}

/**
 * Educational Tamper Utility: Deliberately alters block data to demonstrate forensic detection.
 */
export function tamperAuditLogEntry(
  index: number,
  tamperedDetails: string
): boolean {
  const chain = getAuditLogEntries();
  if (index < 0 || index >= chain.length) return false;

  // Modify data without recalculating the hash
  chain[index].details = tamperedDetails;
  localStorage.setItem(AUDIT_STORAGE_KEY, JSON.stringify(chain));
  return true;
}

/**
 * Generates an exportable Forensic Audit Report in Markdown format.
 */
export async function exportForensicReportMarkdown(): Promise<string> {
  const chain = getAuditLogEntries();
  const integrity = await verifyAuditChainIntegrity();

  let md = `# SECUREVAULTAPP FORENSIC AUDIT REPORT\n`;
  md += `Exported: ${new Date().toISOString()} (UTC)\n`;
  md += `Total Log Entries: ${chain.length}\n`;
  md += `Chain Integrity: ${integrity.isValid ? 'PASSED (VERIFIED)' : 'FAILED (TAMPER DETECTED)'}\n`;
  md += `Verification Message: ${integrity.reason}\n\n`;

  md += `## CRYPTOGRAPHIC HASH CHAIN SUMMARY\n\n`;
  md += `| Block # | Timestamp (UTC) | Actor | Action | Status | Payload Hash (SHA-256) |\n`;
  md += `|:---:|:---|:---|:---|:---:|:---|\n`;

  for (const entry of chain) {
    const shortHash = `${entry.hash.slice(0, 10)}...${entry.hash.slice(-8)}`;
    md += `| ${entry.index} | ${entry.timestamp} | ${entry.actorEmail} | ${entry.action} | ${entry.status} | \`${shortHash}\` |\n`;
  }

  md += `\n## DETAILED EVENT LOGS\n\n`;
  for (const entry of chain) {
    md += `### Block #${entry.index} - ${entry.action}\n`;
    md += `- **Event ID**: ${entry.id}\n`;
    md += `- **Timestamp**: ${entry.timestamp}\n`;
    md += `- **Actor**: ${entry.actorEmail} (ID: ${entry.actorId})\n`;
    md += `- **Resource**: ${entry.resourceType} (${entry.resourceId})\n`;
    md += `- **Status**: ${entry.status}\n`;
    md += `- **Details**: ${entry.details}\n`;
    md += `- **Previous Block Hash**: \`${entry.prevHash}\`\n`;
    md += `- **Block Hash**: \`${entry.hash}\`\n\n`;
  }

  md += `---\n*Report generated by SecureVaultApp Digital Forensics Engine*\n`;
  return md;
}
