import React, { useEffect, useRef, useState } from 'react';

const MAX_SOURCE_BYTES = 15 * 1024 * 1024;
const OUTPUT_SIZE = 512;

const prepareAvatarImage = async (file) => {
  if (!file || !file.type.startsWith('image/')) {
    throw new Error('Wybierz plik graficzny, np. JPG, PNG, BMP lub WebP.');
  }
  if (file.size > MAX_SOURCE_BYTES) {
    throw new Error('Obrazek jest za duży. Wybierz plik do 15 MB.');
  }
  const sourceUrl = URL.createObjectURL(file);
  try {
    const source = new Image();
    source.src = sourceUrl;
    await source.decode();
    if (!source.naturalWidth || !source.naturalHeight) throw new Error('Nieprawidłowy obrazek.');
    const canvas = document.createElement('canvas');
    canvas.width = OUTPUT_SIZE;
    canvas.height = OUTPUT_SIZE;
    const context = canvas.getContext('2d');
    if (!context) throw new Error('Nie można przygotować obrazka.');
    const crop = Math.min(source.naturalWidth, source.naturalHeight);
    context.drawImage(
      source,
      (source.naturalWidth - crop) / 2,
      (source.naturalHeight - crop) / 2,
      crop,
      crop,
      0,
      0,
      OUTPUT_SIZE,
      OUTPUT_SIZE,
    );
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/webp', 0.86));
    if (!blob || !['image/webp', 'image/png'].includes(blob.type)) {
      throw new Error('Nie można przygotować obrazka.');
    }
    return blob;
  } finally {
    URL.revokeObjectURL(sourceUrl);
  }
};

const AvatarImageInput = ({ imageBlob, onChange, onError }) => {
  const fileInput = useRef(null);
  const pasteArea = useRef(null);
  const [previewUrl, setPreviewUrl] = useState('');
  const [hint, setHint] = useState('');

  useEffect(() => {
    if (!imageBlob) {
      setPreviewUrl('');
      return undefined;
    }
    const url = URL.createObjectURL(imageBlob);
    setPreviewUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [imageBlob]);

  const handleImageFile = async (file) => {
    try {
      const prepared = await prepareAvatarImage(file);
      onChange(prepared);
      onError('');
      setHint('Obrazek jest gotowy. Zapisz profil, aby go zastosować.');
    } catch (error) {
      onError(error.message || 'Nie można odczytać obrazka.');
    }
  };

  const pasteFromClipboard = async () => {
    if (navigator.clipboard?.read) {
      try {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          const type = item.types.find((value) => value.startsWith('image/'));
          if (type) {
            await handleImageFile(await item.getType(type));
            return;
          }
        }
        onError('W schowku nie ma obrazka.');
        return;
      } catch {
        // Some browsers only expose images through the normal paste event.
      }
    }
    pasteArea.current?.focus();
    setHint('Naciśnij Ctrl+V (na Macu ⌘V), aby wkleić obrazek.');
  };

  const handlePaste = (event) => {
    const file = [...(event.clipboardData?.items || [])]
      .find((item) => item.type.startsWith('image/'))?.getAsFile();
    if (!file) return;
    event.preventDefault();
    void handleImageFile(file);
  };

  return React.createElement('div', { className: 'avatar-upload' },
    React.createElement('div', { className: 'avatar-upload-actions' },
      React.createElement('input', {
        ref: fileInput,
        type: 'file',
        accept: 'image/jpeg,image/png,image/webp,image/bmp,image/gif,.jpg,.jpeg,.png,.webp,.bmp,.gif',
        className: 'avatar-file-input',
        'aria-label': 'Wybierz obrazek avatara',
        onChange: (event) => {
          const file = event.target.files?.[0];
          if (file) void handleImageFile(file);
          event.target.value = '';
        },
      }),
      React.createElement('button', {
        type: 'button', className: 'btn btn-secondary',
        onClick: () => fileInput.current?.click(),
      }, '📁 Wybierz obrazek'),
      React.createElement('button', {
        type: 'button', className: 'btn btn-secondary', onClick: pasteFromClipboard,
      }, '📋 Wklej ze schowka'),
    ),
    React.createElement('div', {
      ref: pasteArea,
      className: 'avatar-paste-area',
      tabIndex: 0,
      role: 'button',
      'aria-label': 'Wklej tutaj obrazek avatara',
      onPaste: handlePaste,
      onDragOver: (event) => event.preventDefault(),
      onDrop: (event) => {
        event.preventDefault();
        const file = event.dataTransfer?.files?.[0];
        if (file) void handleImageFile(file);
      },
    }, previewUrl
      ? React.createElement('img', { src: previewUrl, alt: 'Podgląd nowego avatara', className: 'avatar-upload-preview' })
      : 'Kliknij tutaj i naciśnij Ctrl+V albo przeciągnij obrazek'),
    imageBlob && React.createElement('button', {
      type: 'button', className: 'avatar-upload-clear',
      onClick: () => { onChange(null); setHint(''); },
    }, 'Usuń wybrany obrazek'),
    hint && React.createElement('p', { className: 'avatar-upload-hint', role: 'status' }, hint),
  );
};

export default AvatarImageInput;
