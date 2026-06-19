import React from 'react';
import ReactDOM from 'react-dom';
import CloseButton from '../buttons/CloseButton';
import Button from '../buttons/Button';
import styled from 'styled-components';
import Text from '../typography/Text';

const ModalWrapper = styled.div`
  position: fixed;
  display: flex;
  justify-content: center;
  align-items: center;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 101;
  background-color: rgba(15, 23, 42, 0.35);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
`;

const StyledModal = styled.div`
  position: relative;
  z-index: 101;
  max-width: 480px;
  min-width: 264px;
  width: 100%;
  text-align: center;
  background: rgba(255, 255, 255, 0.95);
  border: 1px solid rgba(226, 232, 240, 0.9);
  border-radius: 20px;
  padding: 2rem 1.5rem;
  margin: 0 1rem;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
  opacity: 0;
  animation: fade-in 0.5s ease-out forwards;

  @keyframes fade-in {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
  }

  @media screen and (min-width: 1024px) {
    padding: 2.5rem 2rem;
    margin: 0;
    min-width: 400px;
    max-width: 520px;
  }
`;

const ModalContent = styled.div`
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  gap: 1.5rem;
`;

const ModalHeading = styled.h2`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.4rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
  letter-spacing: -0.02em;
  margin: 0;
`;

const IconWrapper = styled.div`
  position: absolute;
  top: 1rem;
  right: 1rem;

  button {
    color: #64748b !important;

    &:hover {
      color: ${({ theme }) => theme.colors.fontColorDark} !important;
    }
  }
`;

const ModalButton = styled(Button)`
  /* TODO: #764ba2 提取到 theme */
  background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2) !important;
  color: ${({ theme }) => theme.colors.lightestBg} !important;
  border: none !important;
  border-radius: 10px !important;
  font-weight: 600 !important;
  padding: 0.65rem 2rem !important;
  box-shadow: 0 4px 20px rgba(102, 126, 234, 0.25) !important;
  transition: all 0.35s cubic-bezier(0.22, 1, 0.36, 1) !important;

  &:hover:not(:disabled) {
    box-shadow: 0 6px 24px rgba(102, 126, 234, 0.35) !important;
    transform: translateY(-1px);
  }
`;

const ModalText = styled(Text)`
  /* TODO: #475569 提取到 theme */
  color: #475569;
  font-size: 0.95rem;
  line-height: 1.6;
`;

interface ModalProps {
  children?: React.ReactNode;
  headingText?: string;
  btnText?: string;
  onClose: () => void;
  onBtnClicked: () => void;
}

const Modal: React.FC<ModalProps> = ({
  children,
  headingText = 'Modal',
  btnText = 'Call to Action',
  onClose,
  onBtnClicked,
}) => {
  return ReactDOM.createPortal(
    <ModalWrapper
      id="wrapper"
      onClick={(e) => {
        if ((e.target as HTMLElement).id === 'wrapper') {
          onClose();
        }
      }}
    >
      <StyledModal>
        <IconWrapper>
          <CloseButton clickHandler={onClose} />
        </IconWrapper>
        <ModalContent>
          <ModalHeading>{headingText}</ModalHeading>
          {children ? (
            children
          ) : (
            <ModalText>
              Lorem ipsum, dolor sit amet consectetur adipisicing elit.
              Blanditiis error aspernatur vel fugiat quisquam aut tempore,
              consequatur quo. Neque officiis magni molestias quasi, accusamus
              rem sunt incidunt inventore esse. Modi.
            </ModalText>
          )}
          <ModalButton primary onClick={onBtnClicked}>
            {btnText}
          </ModalButton>
        </ModalContent>
      </StyledModal>
    </ModalWrapper>,
    document.getElementById('modal') as HTMLElement,
  );
};

const initialModalData = {
  children: () => (
    <ModalText>
      Lorem ipsum dolor sit amet consectetur adipisicing elit. Reiciendis rerum
      omnis, minima perferendis, illum quasi expedita quo saepe fuga nulla
      cupiditate. Reprehenderit fugit placeat error corrupti illo ut? Numquam
      repellat molestias autem porro. Autem enim asperiores voluptatem itaque
      libero aspernatur cupiditate porro atque vel. Esse numquam tempora hic
      soluta excepturi?
    </ModalText>
  ),
  headingText: 'Modal',
  btnText: 'Button',
};

export default Modal;
export { initialModalData };
