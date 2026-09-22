import React from 'react';

const IMAGE_AVATARS = {
  'boy-teal': { src: '/avatars/boy-teal.png', label: 'Chłopiec w turkusowej bluzie' },
  'boy-glasses': { src: '/avatars/boy-glasses.png', label: 'Chłopiec w okularach' },
  'girl-redhair': { src: '/avatars/girl-redhair.png', label: 'Dziewczynka z rudym warkoczem' },
  'girl-brunette': { src: '/avatars/girl-brunette.png', label: 'Dziewczynka w fioletowej bluzie' },
  'girl-puffs': { src: '/avatars/girl-puffs.png', label: 'Dziewczynka w koralowej bluzie' },
};

export const avatarLabel = (value) => IMAGE_AVATARS[value]?.label || value || 'Avatar';

const ChildAvatar = ({ value, size = '1em', className = '' }) => {
  const image = IMAGE_AVATARS[value];
  if (!image) return React.createElement('span', { className, 'aria-label': avatarLabel(value), role: 'img' }, value || '👤');
  return React.createElement('img', {
    src: image.src,
    alt: image.label,
    className: `child-avatar-image ${className}`.trim(),
    loading: 'lazy',
    decoding: 'async',
    style: { width: size, height: size },
  });
};

export default ChildAvatar;
