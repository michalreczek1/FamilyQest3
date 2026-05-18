import React from 'react';
import { createPortal } from 'react-dom';

const ModalOverlay = ({
  children,
  ...props
}) => createPortal(React.createElement("div", props, children), document.body);

export default ModalOverlay;
