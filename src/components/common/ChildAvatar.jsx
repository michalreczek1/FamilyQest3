import React from 'react';
import { buildApiUrl } from '../../lib/api.js';

const UPLOADED_AVATAR_PATTERN = /^u_[0-9a-f]{24}$/;

const IMAGE_AVATARS = {
  'jozek': { src: '/avatars/jozek.png', label: 'Józek' },
  'franek': { src: '/avatars/franek.png', label: 'Franek' },
  'boy-teal': { src: '/avatars/boy-teal.png', label: 'Chłopiec w turkusowej bluzie' },
  'boy-glasses': { src: '/avatars/boy-glasses.png', label: 'Chłopiec w okularach' },
  'girl-redhair': { src: '/avatars/girl-redhair.png', label: 'Dziewczynka z rudym warkoczem' },
  'girl-brunette': { src: '/avatars/girl-brunette.png', label: 'Dziewczynka w fioletowej bluzie' },
  'girl-puffs': { src: '/avatars/girl-puffs.png', label: 'Dziewczynka w koralowej bluzie' },
};

export const avatarLabel = (value) => UPLOADED_AVATAR_PATTERN.test(value || '')
  ? 'Własny avatar'
  : IMAGE_AVATARS[value]?.label || value || 'Avatar';

const ChildAvatar = ({ value, size = '1em', className = '' }) => {
  const image = UPLOADED_AVATAR_PATTERN.test(value || '')
    ? { src: buildApiUrl(`/api/avatars/${value}`), label: 'Własny avatar' }
    : IMAGE_AVATARS[value];
  if (!image) return React.createElement('span', { className, 'aria-label': avatarLabel(value), role: 'img' }, value || '👤');
  return React.createElement('img', {
    src: image.src,
    alt: image.label,
    className: `child-avatar-image ${className}`.trim(),
    decoding: 'async',
    style: { width: size, height: size },
  });
};

export default ChildAvatar;
