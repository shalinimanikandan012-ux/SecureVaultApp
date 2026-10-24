/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Digital Forensics & Audit Module
 * Immutable Append-Oriented SHA-256 Hash Chain with Verification & Report Export
 */

import React, { useEffect, useState } from 'react';
import {
  GitCommit,
  Search,
  Filter,
  Download,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  FileText,
  Info,
  Clock,
  ShieldCheck,
  User,
} from 'lucide-react';
import {
  exportForensicReportMarkdown,
  getAuditLogEntries,
  verifyAuditChainIntegrity,
} from '../../services/auditService';
import { AuditLogEntry, HashChainVerificationResult } from '../../types';

export const ForensicsView: React.FC = () => {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'SUCCESS' | 'FAILURE' | 'TAMPER_DETECTED'>('ALL');
  const [verificationResult, setVerificationResult] = useState<HashChainVerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);

  useEffect(() => {
    loadEntries();
  }, []);

  const loadEntries = async () => {
    const list = getAuditLogEntries();
    setEntries(list);
    runVerification();
  };

  const runVerification = async () => {
    setIsVerifying(true);
    const res = await verifyAuditChainIntegrity();
    setVerificationResult(res);
    setIsVerifying(false);
  };

  const handleExportMarkdown = async () => {
    const md = await exportForensicReportMarkdown();
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `securevault-forensic-audit-report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportJson = () => {
    const data = {
      exportedAt: new Date().toISOString(),
      chainLength: entries.length,
      integrity: verificationResult,
      records: entries,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `securevault-forensic-audit-chain-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredEntries = entries.filter((e) => {
    const matchesSearch =
      e.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.actorEmail.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.details.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.hash.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesStatus =
      statusFilter === 'ALL' || e.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  const formatTimestamp = (iso: string) => {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return iso;
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header & Forensic Status */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <GitCommit className="w-5 h-5 text-cyan-400" />
            <span>Digital Forensics & Tamper-Evident Audit Chain</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Chronological append-oriented audit logs bound by SHA-256 cryptographic hash chaining (H_n = SHA256(H_prev + payload)).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={runVerification}
            disabled={isVerifying}
            className="py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>{isVerifying ? 'Verifying...' : 'Recalculate Chain'}</span>
          </button>

          <button
            onClick={handleExportMarkdown}
            className="py-1.5 px-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Report (.md)</span>
          </button>
        </div>
      </div>

      {/* Forensic Integrity Banner */}
      {verificationResult && (
        <div
          className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs ${
            verificationResult.isValid
              ? 'bg-emerald-950/20 border-emerald-800/60 text-emerald-300'
              : 'bg-rose-950/30 border-rose-800/80 text-rose-300'
          }`}
        >
          <div className="flex items-center gap-2.5">
            {verificationResult.isValid ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
            )}
            <div>
              <div className="font-semibold text-sm">
                {verificationResult.isValid
                  ? 'Cryptographic Hash Chain Verified (Intact)'
                  : 'TAMPER DETECTED: Hash Chain Severed!'}
              </div>
              <div className="text-[11px] opacity-90 mt-0.5">
                {verificationResult.reason}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 text-[11px] font-mono tabular-nums shrink-0 self-end sm:self-auto">
            <span>{verificationResult.totalChecked} blocks checked</span>
            <span aria-hidden="true">·</span>
            <button
              onClick={handleExportJson}
              className="text-cyan-400 hover:underline"
            >
              Export JSON Chain
            </button>
          </div>
        </div>
      )}

      {/* Academic Cybersecurity Footnote: Hash Chain Limitations */}
      <div className="p-3 bg-[#0b1120] border border-slate-800 rounded-lg text-xs text-slate-400 flex items-start gap-2.5">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-[11px] leading-relaxed">
          <strong className="text-slate-200">College Forensics Note:</strong> A hash chain guarantees
          tamper-evidence against localized modifications within the database. However, if an adversary possesses
          root access to modify both the rows and recompute all forward hashes, an external trust anchor (e.g.,
          periodic signed Merkle root checkpoints or an immutable append-only WORM archive) is required for non-repudiation.
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-[#0f172a] border border-slate-800 rounded-xl p-3">
        <div className="relative flex-1 max-w-md">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by action, actor, details, or hash..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400 text-[11px]">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as any)}
            className="bg-[#0b1120] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Outcomes</option>
            <option value="SUCCESS">Success Only</option>
            <option value="FAILURE">Failures</option>
            <option value="TAMPER_DETECTED">Tamper Alerts</option>
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#0b1120] border-b border-slate-800 text-slate-400 text-[11px]">
                <th className="py-2.5 px-4 font-medium w-16">Block #</th>
                <th className="py-2.5 px-4 font-medium">Timestamp (UTC)</th>
                <th className="py-2.5 px-4 font-medium">Actor</th>
                <th className="py-2.5 px-4 font-medium">Action</th>
                <th className="py-2.5 px-4 font-medium">Outcome</th>
                <th className="py-2.5 px-4 font-medium">Payload SHA-256 Hash</th>
                <th className="py-2.5 px-4 font-medium text-right">Inspection</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {filteredEntries.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-500">
                    No matching audit records found.
                  </td>
                </tr>
              ) : (
                filteredEntries.map((entry) => (
                  <tr
                    key={entry.id}
                    className="hover:bg-slate-800/30 transition-colors"
                  >
                    <td className="py-3 px-4 font-mono font-semibold text-cyan-400 tabular-nums">
                      #{entry.index}
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px] tabular-nums whitespace-nowrap">
                      {formatTimestamp(entry.timestamp)}
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-200 whitespace-nowrap">
                      {entry.actorEmail}
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-300 text-[11px]">
                      {entry.action}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {entry.status === 'SUCCESS' ? (
                        <span className="text-emerald-400 font-medium">Success</span>
                      ) : entry.status === 'TAMPER_DETECTED' ? (
                        <span className="text-rose-400 font-bold">Tamper Detected</span>
                      ) : (
                        <span className="text-amber-400 font-medium">Failure</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 text-[10px]">
                      <span className="bg-[#0b1120] px-1.5 py-0.5 rounded border border-slate-800">
                        {entry.hash.slice(0, 10)}...{entry.hash.slice(-8)}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedEntry(entry)}
                        className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Entry Detail Modal */}
      {selectedEntry && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-2xl relative">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <GitCommit className="w-4 h-4 text-cyan-400" />
                <span>Forensic Block #{selectedEntry.index} Details</span>
              </h3>
              <button
                onClick={() => setSelectedEntry(null)}
                className="text-slate-400 hover:text-slate-200 text-xs"
              >
                Close
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div className="p-3 bg-[#070b14] rounded-lg border border-slate-800 space-y-2">
                <div>
                  <span className="text-slate-500">Event ID: </span>
                  <span className="text-slate-300">{selectedEntry.id}</span>
                </div>
                <div>
                  <span className="text-slate-500">Timestamp: </span>
                  <span className="text-slate-300">{selectedEntry.timestamp}</span>
                </div>
                <div>
                  <span className="text-slate-500">Actor: </span>
                  <span className="text-slate-200">{selectedEntry.actorEmail} ({selectedEntry.actorId})</span>
                </div>
                <div>
                  <span className="text-slate-500">Action: </span>
                  <span className="text-cyan-400">{selectedEntry.action}</span>
                </div>
                <div>
                  <span className="text-slate-500">Resource: </span>
                  <span className="text-slate-300">{selectedEntry.resourceType} ({selectedEntry.resourceId})</span>
                </div>
                <div>
                  <span className="text-slate-500">Status: </span>
                  <span className="text-emerald-400">{selectedEntry.status}</span>
                </div>
                <div>
                  <span className="text-slate-500">Details: </span>
                  <span className="text-slate-300 font-sans">{selectedEntry.details}</span>
                </div>
              </div>

              {/* Hashes */}
              <div className="p-3 bg-[#070b14] rounded-lg border border-slate-800 space-y-2 text-[10px]">
                <div>
                  <div className="text-slate-500 mb-0.5">Previous Block Hash (prevHash):</div>
                  <div className="text-slate-400 break-all select-all bg-[#0b1120] p-1.5 rounded">
                    {selectedEntry.prevHash}
                  </div>
                </div>
                <div>
                  <div className="text-cyan-400 mb-0.5">Canonical Block Hash (SHA-256):</div>
                  <div className="text-cyan-300 break-all select-all bg-[#0b1120] p-1.5 rounded font-bold">
                    {selectedEntry.hash}
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedEntry(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
