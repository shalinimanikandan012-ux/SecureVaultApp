/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Secure File Vault
 * Real Client-Side AES-256-GCM File Encryption, SHA-256 Pre/Post Integrity Verification & Download
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  FolderLock,
  Upload,
  Download,
  Trash2,
  File,
  Lock,
  Unlock,
  AlertCircle,
  CheckCircle2,
  HardDrive,
  Clock,
  ShieldCheck,
  FileText,
  KeyRound,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useVault } from '../../context/VaultContext';
import { recordAuditEvent } from '../../services/auditService';
import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  decryptAESGCM,
  encryptAESGCM,
  sha256Hex,
} from '../../services/crypto';
import {
  deleteEncryptedFile,
  getEncryptedFiles,
  logSecurityEvent,
  saveEncryptedFile,
} from '../../services/storage';
import { EncryptedFileRecord } from '../../types';

interface FileVaultViewProps {
  onOpenUnlockModal: () => void;
  onOpenSetupModal: () => void;
}

const MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024; // 15MB safe client-side threshold

export const FileVaultView: React.FC<FileVaultViewProps> = ({
  onOpenUnlockModal,
  onOpenSetupModal,
}) => {
  const { currentUser } = useAuth();
  const { isVaultConfigured, isVaultUnlocked, getMasterKeyForOperations } = useVault();

  const [files, setFiles] = useState<EncryptedFileRecord[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (currentUser) {
      loadFiles();
    }
  }, [currentUser]);

  const loadFiles = async () => {
    if (!currentUser) return;
    setIsLoading(true);
    try {
      const records = await getEncryptedFiles(currentUser.id);
      setFiles(records);
    } catch (err) {
      console.error('Failed to load files:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (!selectedFile || !currentUser) return;

    const masterKey = getMasterKeyForOperations();
    if (!masterKey) {
      setUploadError('Vault is locked. Unlock before uploading encrypted files.');
      return;
    }

    if (selectedFile.size > MAX_FILE_SIZE_BYTES) {
      setUploadError('File exceeds 15MB limit for secure in-browser cryptographic processing.');
      return;
    }

    setIsUploading(true);
    setUploadError(null);

    try {
      const fileBuffer = await selectedFile.arrayBuffer();

      // Step 1: Compute original SHA-256 checksum for forensic verification
      const sha256Checksum = await sha256Hex(fileBuffer);

      // Step 2: Real AES-256-GCM encryption with fresh 96-bit nonce
      const payload = await encryptAESGCM(fileBuffer, masterKey, selectedFile.name);

      const fileRecord: EncryptedFileRecord = {
        id: `file-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        userId: currentUser.id,
        name: selectedFile.name.replace(/[^a-zA-Z0-9._-]/g, '_'),
        size: selectedFile.size,
        mimeType: selectedFile.type || 'application/octet-stream',
        sha256Checksum,
        encryptedPayload: payload,
        uploadedAt: new Date().toISOString(),
      };

      await saveEncryptedFile(fileRecord);
      setFiles((prev) => [fileRecord, ...prev]);

      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'FILE_UPLOADED_ENCRYPTED',
        severity: 'INFO',
        message: `File encrypted & committed to vault: ${fileRecord.name} (${fileRecord.size} bytes)`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      await recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'FILE_UPLOAD',
        resourceType: 'ENCRYPTED_FILE',
        resourceId: fileRecord.id,
        status: 'SUCCESS',
        details: `File "${fileRecord.name}" encrypted with AES-256-GCM (SHA256: ${sha256Checksum.slice(0, 16)}...)`,
      });

      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (err) {
      console.error('File encryption failed:', err);
      setUploadError('Cryptographic encryption or storage failed.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleDownloadAndDecrypt = async (record: EncryptedFileRecord) => {
    const masterKey = getMasterKeyForOperations();
    if (!masterKey || !currentUser) {
      setUploadError('Vault is locked. Unlock to decrypt and download files.');
      return;
    }

    setDownloadingId(record.id);

    try {
      // Step 1: Decrypt payload using AES-256-GCM
      const decryptedBuffer = await decryptAESGCM(
        record.encryptedPayload,
        masterKey,
        record.name // verify AAD matches file name
      );

      // Step 2: Integrity Verification — Check SHA-256 against stored checksum
      const computedChecksum = await sha256Hex(decryptedBuffer);

      if (computedChecksum !== record.sha256Checksum) {
        logSecurityEvent({
          userId: currentUser.id,
          userEmail: currentUser.email,
          type: 'FILE_INTEGRITY_FAILED',
          severity: 'CRITICAL',
          message: `Checksum mismatch for file: ${record.name}. Possible data tampering.`,
          timestamp: new Date().toISOString(),
          ipAddress: '127.0.0.1',
          userAgent: navigator.userAgent,
        });

        await recordAuditEvent({
          actorId: currentUser.id,
          actorEmail: currentUser.email,
          action: 'FILE_DECRYPT_VERIFY',
          resourceType: 'ENCRYPTED_FILE',
          resourceId: record.id,
          status: 'TAMPER_DETECTED',
          details: `SHA-256 checksum mismatch on download. Expected ${record.sha256Checksum}, calculated ${computedChecksum}`,
        });

        alert('CRITICAL SECURITY ALERT: Decrypted file checksum mismatch! Download aborted.');
        setDownloadingId(null);
        return;
      }

      // Step 3: Trigger safe browser download
      const blob = new Blob([decryptedBuffer], { type: record.mimeType });
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = record.name;
      a.click();
      URL.revokeObjectURL(downloadUrl);

      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'FILE_DOWNLOADED_DECRYPTED',
        severity: 'INFO',
        message: `File decrypted and verified: ${record.name}`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      await recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'FILE_DOWNLOAD',
        resourceType: 'ENCRYPTED_FILE',
        resourceId: record.id,
        status: 'SUCCESS',
        details: `File "${record.name}" decrypted and verified against SHA-256 checksum`,
      });
    } catch (err) {
      console.error('Decryption failed:', err);
      alert('Decryption failed: Ciphertext or authentication tag was altered.');
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDeleteFile = async () => {
    if (!deletingId || !currentUser) return;
    const toDelete = files.find((f) => f.id === deletingId);

    const success = await deleteEncryptedFile(deletingId, currentUser.id);
    if (success) {
      setFiles((prev) => prev.filter((f) => f.id !== deletingId));

      logSecurityEvent({
        userId: currentUser.id,
        userEmail: currentUser.email,
        type: 'FILE_DELETED',
        severity: 'INFO',
        message: `Encrypted file purged from storage: ${toDelete?.name || deletingId}`,
        timestamp: new Date().toISOString(),
        ipAddress: '127.0.0.1',
        userAgent: navigator.userAgent,
      });

      await recordAuditEvent({
        actorId: currentUser.id,
        actorEmail: currentUser.email,
        action: 'FILE_DELETE',
        resourceType: 'ENCRYPTED_FILE',
        resourceId: deletingId,
        status: 'SUCCESS',
        details: `File record destroyed from IndexedDB: ${toDelete?.name}`,
      });
    }
    setDeletingId(null);
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  const formatTimestamp = (iso: string) => {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return iso;
    }
  };

  if (!isVaultUnlocked) {
    return (
      <div className="max-w-4xl mx-auto py-12 px-4 text-center">
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-8 max-w-lg mx-auto shadow-2xl">
          <div className="w-12 h-12 rounded-xl bg-amber-950/60 border border-amber-800/80 text-amber-400 mx-auto flex items-center justify-center mb-4">
            <Lock className="w-6 h-6" />
          </div>
          <h2 className="text-xl font-bold text-white mb-2">
            Secure File Vault is Locked
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed mb-6">
            Files stored in the vault are chunked and encrypted with AES-256-GCM.
            Unlock the vault with your master password to decrypt, download, or upload
            new confidential documents.
          </p>

          <div className="p-3 bg-[#0b1120] border border-slate-800 rounded-lg text-left text-xs mb-6 space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span>Encrypted Files in Storage:</span>
              <span className="font-mono text-cyan-400 font-semibold tabular-nums">
                {files.length} files
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-400">
              <span>Integrity Verification Mode:</span>
              <span className="font-mono text-emerald-400">SHA-256 Pre/Post Verification</span>
            </div>
          </div>

          {!isVaultConfigured ? (
            <button
              onClick={onOpenSetupModal}
              className="w-full py-2.5 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2"
            >
              <span>Initialize Master Key</span>
            </button>
          ) : (
            <button
              onClick={onOpenUnlockModal}
              className="w-full py-2.5 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2"
            >
              <Unlock className="w-4 h-4" />
              <span>Unlock Encrypted Vault</span>
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Upload & Dropzone Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <FolderLock className="w-5 h-5 text-cyan-400" />
            <span>Encrypted File Vault</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Client-side authenticated AES-256-GCM encryption with SHA-256 checksum integrity verification.
          </p>
        </div>

        <div>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={isUploading}
            className="py-2 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            <Upload className="w-4 h-4" />
            <span>{isUploading ? 'Encrypting & Storing...' : 'Upload & Encrypt File'}</span>
          </button>
        </div>
      </div>

      {uploadError && (
        <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/80 flex items-start gap-2.5 text-xs text-rose-300">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>{uploadError}</div>
        </div>
      )}

      {/* Files Table / List */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3 text-xs text-slate-400">
            <span className="font-semibold text-slate-200">Stored Files ({files.length})</span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums">
              Total: {formatBytes(files.reduce((a, b) => a + b.size, 0))}
            </span>
          </div>
          <span className="text-[11px] font-mono text-cyan-400">AES-256-GCM / 96-bit IV</span>
        </div>

        {files.length === 0 ? (
          <div className="text-center py-16 p-6">
            <HardDrive className="w-8 h-8 text-slate-600 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-300">File Vault is Empty</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              Upload documents, configuration keys, or certificates (up to 15MB) to test
              zero-knowledge authenticated encryption and integrity check.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800 text-xs">
            {files.map((file) => (
              <div
                key={file.id}
                className="p-4 hover:bg-slate-800/30 transition-colors flex flex-col md:flex-row items-start md:items-center justify-between gap-3"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-9 h-9 rounded-lg bg-[#0b1120] border border-slate-800 flex items-center justify-center text-cyan-400 shrink-0">
                    <File className="w-4 h-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="font-semibold text-slate-200 truncate flex items-center gap-2">
                      <span>{file.name}</span>
                    </div>
                    <div className="flex items-center gap-2 text-[11px] text-slate-400 mt-0.5 font-mono tabular-nums">
                      <span>{formatBytes(file.size)}</span>
                      <span aria-hidden="true">·</span>
                      <span>Uploaded {formatTimestamp(file.uploadedAt)}</span>
                      <span aria-hidden="true">·</span>
                      <span className="text-slate-500 truncate max-w-[200px]" title={file.sha256Checksum}>
                        SHA256: {file.sha256Checksum.slice(0, 12)}...
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-end md:self-auto">
                  <button
                    onClick={() => handleDownloadAndDecrypt(file)}
                    disabled={downloadingId === file.id}
                    className="py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors flex items-center gap-1.5 font-medium disabled:opacity-50"
                    title="Decrypt in memory and download"
                  >
                    <Download className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{downloadingId === file.id ? 'Decrypting...' : 'Decrypt & Download'}</span>
                  </button>
                  <button
                    onClick={() => setDeletingId(file.id)}
                    className="p-1.5 hover:text-rose-400 hover:bg-slate-800 text-slate-500 rounded-lg transition-colors"
                    title="Delete file"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      {deletingId && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-sm bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-2xl">
            <h3 className="text-sm font-bold text-white mb-2">
              Permanently Purge Encrypted File?
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed mb-4">
              This action will delete the encrypted payload from storage. The file will be
              unrecoverable.
            </p>
            <div className="flex items-center justify-end gap-2">
              <button
                onClick={() => setDeletingId(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteFile}
                className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs rounded-lg transition-colors"
              >
                Purge Record
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
