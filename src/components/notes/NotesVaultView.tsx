/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Encrypted Notes Vault
 * Zero-Knowledge AES-256-GCM Note Operations with Raw Ciphertext Inspector
 */

import React, { useState } from 'react';
import {
  FileKey,
  Plus,
  Search,
  Lock,
  Unlock,
  Trash2,
  Edit3,
  Tag,
  Folder,
  Eye,
  EyeOff,
  Clock,
  ShieldCheck,
  AlertCircle,
  X,
  Binary,
} from 'lucide-react';
import { useVault } from '../../context/VaultContext';
import { DecryptedNote, EncryptedNote } from '../../types';

interface NotesVaultViewProps {
  onOpenUnlockModal: () => void;
  onOpenSetupModal: () => void;
}

export const NotesVaultView: React.FC<NotesVaultViewProps> = ({
  onOpenUnlockModal,
  onOpenSetupModal,
}) => {
  const {
    isVaultConfigured,
    isVaultUnlocked,
    decryptedNotes,
    rawEncryptedNotes,
    createNote,
    editNote,
    removeNote,
    isLoadingNotes,
  } = useVault();

  // Search & Filter State
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [viewingCiphertextId, setViewingCiphertextId] = useState<string | null>(null);

  // Editor Modal State
  const [isEditorOpen, setIsEditorOpen] = useState(false);
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null);
  const [noteTitle, setNoteTitle] = useState('');
  const [noteContent, setNoteContent] = useState('');
  const [noteCategory, setNoteCategory] = useState('Confidential');
  const [noteTags, setNoteTags] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [editorError, setEditorError] = useState<string | null>(null);

  // Delete Confirmation State
  const [deletingNoteId, setDeletingNoteId] = useState<string | null>(null);

  // Filter notes
  const categories = [
    'All',
    ...Array.from(new Set(rawEncryptedNotes.map((n) => n.category || 'General'))),
  ];

  const filteredNotes = decryptedNotes.filter((note) => {
    const matchesSearch =
      note.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.content.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.tags.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesCategory =
      selectedCategory === 'All' || note.category === selectedCategory;

    return matchesSearch && matchesCategory;
  });

  const handleOpenCreate = () => {
    setEditingNoteId(null);
    setNoteTitle('');
    setNoteContent('');
    setNoteCategory('Confidential');
    setNoteTags('');
    setEditorError(null);
    setIsEditorOpen(true);
  };

  const handleOpenEdit = (note: DecryptedNote) => {
    setEditingNoteId(note.id);
    setNoteTitle(note.title);
    setNoteContent(note.content);
    setNoteCategory(note.category);
    setNoteTags(note.tags.join(', '));
    setEditorError(null);
    setIsEditorOpen(true);
  };

  const handleSaveNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteTitle.trim() || !noteContent.trim()) {
      setEditorError('Title and content cannot be empty.');
      return;
    }

    setIsSaving(true);
    setEditorError(null);

    const tagsArray = noteTags
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);

    try {
      if (editingNoteId) {
        const res = await editNote(
          editingNoteId,
          noteTitle,
          noteContent,
          noteCategory,
          tagsArray
        );
        if (!res.success) {
          setEditorError(res.error || 'Failed to update encrypted note.');
          setIsSaving(false);
          return;
        }
      } else {
        const res = await createNote(
          noteTitle,
          noteContent,
          noteCategory,
          tagsArray
        );
        if (!res.success) {
          setEditorError(res.error || 'Failed to encrypt and save note.');
          setIsSaving(false);
          return;
        }
      }

      setIsEditorOpen(false);
    } catch {
      setEditorError('Unexpected encryption failure.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deletingNoteId) return;
    await removeNote(deletingNoteId);
    setDeletingNoteId(null);
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

  // If vault is locked or uninitialized, show locked view with explanation
  if (!isVaultUnlocked) {
    return (
      <div className="max-w-4xl mx-auto py-12 px-4 text-center">
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-8 max-w-lg mx-auto shadow-2xl">
          <div className="w-12 h-12 rounded-xl bg-amber-950/60 border border-amber-800/80 text-amber-400 mx-auto flex items-center justify-center mb-4">
            <Lock className="w-6 h-6" />
          </div>
          <h2 className="text-xl font-bold text-white mb-2">
            Encrypted Notes Vault is Locked
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed mb-6">
            To view, decrypt, or create notes, unlock the vault using your master
            password. Note contents are encrypted at rest with AES-256-GCM and only exist
            as plaintext in volatile client memory while unlocked.
          </p>

          <div className="p-3 bg-[#0b1120] border border-slate-800 rounded-lg text-left text-xs mb-6 space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span>Encrypted Records in Storage:</span>
              <span className="font-mono text-cyan-400 font-semibold tabular-nums">
                {rawEncryptedNotes.length} notes
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-400">
              <span>In-Memory Master Key:</span>
              <span className="font-mono text-amber-400">Not Present (Purged)</span>
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
      {/* Action Header & Search */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4 bg-[#0f172a] border border-slate-800 rounded-xl p-4">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search in decrypted notes (in-memory only)..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Category Filter & New Note Action */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Folder className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="bg-[#0b1120] border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleOpenCreate}
            className="py-1.5 px-3.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5 shrink-0"
          >
            <Plus className="w-4 h-4" />
            <span>New Encrypted Note</span>
          </button>
        </div>
      </div>

      {/* Notes Grid */}
      {isLoadingNotes ? (
        <div className="text-center py-12 text-slate-500 text-xs font-mono">
          Decrypting payloads with AES-256-GCM...
        </div>
      ) : filteredNotes.length === 0 ? (
        <div className="text-center py-16 bg-[#0f172a] border border-slate-800 rounded-xl p-8">
          <FileKey className="w-8 h-8 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-300">
            {searchQuery ? 'No matching notes found' : 'Vault has no encrypted notes'}
          </h3>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            {searchQuery
              ? 'Try modifying your search term or category filter.'
              : 'Create your first note to verify client-side AES-256-GCM encryption and persistent payload storage.'}
          </p>
          {!searchQuery && (
            <button
              onClick={handleOpenCreate}
              className="mt-4 px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors inline-flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Create First Note</span>
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredNotes.map((note) => {
            const raw = rawEncryptedNotes.find((r) => r.id === note.id);
            const isCiphertextOpen = viewingCiphertextId === note.id;

            return (
              <div
                key={note.id}
                className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 flex flex-col justify-between hover:border-slate-700 transition-colors"
              >
                <div>
                  {/* Note Header: Unboxed metadata */}
                  <div className="flex items-center justify-between gap-2 text-[11px] text-slate-400 mb-2">
                    <span className="text-cyan-400 font-medium">{note.category}</span>
                    <div className="flex items-center gap-1.5 font-mono text-slate-500 tabular-nums">
                      <Clock className="w-3 h-3" />
                      <span>{formatTimestamp(note.updatedAt)}</span>
                    </div>
                  </div>

                  <h3 className="text-sm font-bold text-white mb-2 leading-snug">
                    {note.title}
                  </h3>

                  {/* Note Content / Ciphertext Toggle */}
                  {isCiphertextOpen && raw ? (
                    <div className="p-2.5 bg-[#070b14] rounded-lg border border-slate-800 text-[10px] font-mono space-y-1.5 mb-3">
                      <div className="text-cyan-400 font-semibold flex items-center justify-between">
                        <span>Stored AES-256-GCM Payload</span>
                        <span className="text-slate-500 text-[9px]">Zero-Knowledge</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Nonce (12B): </span>
                        <span className="text-slate-300 break-all select-all">
                          {raw.encryptedPayload.nonce}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Auth Tag (16B): </span>
                        <span className="text-amber-400/90 break-all select-all">
                          {raw.encryptedPayload.tag}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Ciphertext: </span>
                        <span className="text-slate-400 break-all select-all">
                          {raw.encryptedPayload.ciphertext.slice(0, 48)}...
                        </span>
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap line-clamp-4 mb-3">
                      {note.content}
                    </p>
                  )}

                  {/* Tags */}
                  {note.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-3">
                      {note.tags.map((t, idx) => (
                        <span
                          key={idx}
                          className="text-[10px] text-slate-400 flex items-center gap-0.5"
                        >
                          <Tag className="w-2.5 h-2.5 text-slate-500" />
                          <span>{t}</span>
                          {idx < note.tags.length - 1 && <span className="text-slate-600">·</span>}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Card Action Controls */}
                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                  <button
                    onClick={() =>
                      setViewingCiphertextId(isCiphertextOpen ? null : note.id)
                    }
                    className="flex items-center gap-1 text-[11px] hover:text-cyan-400 transition-colors"
                    title="Inspect raw AES-256-GCM ciphertext in storage"
                  >
                    <Binary className="w-3.5 h-3.5 text-cyan-500" />
                    <span>{isCiphertextOpen ? 'View Plaintext' : 'Inspect Ciphertext'}</span>
                  </button>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleOpenEdit(note)}
                      className="p-1 hover:text-cyan-400 hover:bg-slate-800 rounded transition-colors"
                      title="Edit Note"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => setDeletingNoteId(note.id)}
                      className="p-1 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
                      title="Delete Note"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Editor Modal */}
      {isEditorOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-2xl relative">
            <button
              onClick={() => setIsEditorOpen(false)}
              className="absolute top-4 right-4 text-slate-500 hover:text-slate-300 p-1"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-2.5 mb-4">
              <FileKey className="w-5 h-5 text-cyan-400" />
              <h2 className="text-base font-bold text-white">
                {editingNoteId ? 'Edit Encrypted Note' : 'Create Encrypted Note'}
              </h2>
            </div>

            {editorError && (
              <div className="mb-4 p-2.5 rounded-lg bg-rose-950/40 border border-rose-800/80 flex items-start gap-2 text-xs text-rose-300">
                <AlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                <div>{editorError}</div>
              </div>
            )}

            <form onSubmit={handleSaveNote} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Note Title
                </label>
                <input
                  type="text"
                  value={noteTitle}
                  onChange={(e) => setNoteTitle(e.target.value)}
                  placeholder="e.g., Incident Response Key Rotation Checklist"
                  className="w-full px-3 py-2 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Category
                  </label>
                  <input
                    type="text"
                    value={noteCategory}
                    onChange={(e) => setNoteCategory(e.target.value)}
                    placeholder="Confidential, Infrastructure, Keys..."
                    className="w-full px-3 py-2 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    Tags (comma-separated)
                  </label>
                  <input
                    type="text"
                    value={noteTags}
                    onChange={(e) => setNoteTags(e.target.value)}
                    placeholder="prod, aws, credential"
                    className="w-full px-3 py-2 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Sensitive Plaintext Content (Encrypted with AES-256-GCM)
                </label>
                <textarea
                  rows={6}
                  value={noteContent}
                  onChange={(e) => setNoteContent(e.target.value)}
                  placeholder="Enter classified or sensitive text payload..."
                  className="w-full px-3 py-2 bg-[#0b1120] border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono text-xs leading-relaxed"
                  required
                />
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] text-slate-500 font-mono">
                  Payload AAD bound to record ID
                </span>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setIsEditorOpen(false)}
                    className="px-3 py-1.5 text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSaving}
                    className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded-lg transition-colors disabled:opacity-50"
                  >
                    {isSaving ? 'Encrypting & Storing...' : 'Save & Encrypt'}
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deletingNoteId && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-sm bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-2xl">
            <h3 className="text-sm font-bold text-white mb-2">
              Permanently Purge Encrypted Note?
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed mb-4">
              This action will destroy the ciphertext and associated authentication tags.
              This cannot be undone.
            </p>
            <div className="flex items-center justify-end gap-2">
              <button
                onClick={() => setDeletingNoteId(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
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
