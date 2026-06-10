import React, { useRef, useContext, useEffect } from 'react';
import Container from '../components/layout/Container';
import { Navigate, Link } from 'react-router-dom';
import HeadingWithLogo from '../components/typography/HeadingWithLogo';
import Button from '../components/buttons/Button';
import { Input } from '../components/forms/Input';
import { Form } from '../components/forms/Form';
import { FormGroup } from '../components/forms/FormGroup';
import { ButtonGroup } from '../components/forms/ButtonGroup';
import { Label } from '../components/forms/Label';
import RelativeWrapper from '../components/layout/RelativeWrapper';
import ShowPasswordButton from '../components/buttons/ShowPasswordButton';
import useScrollToTopOnPageLoad from '../hooks/useScrollToTopOnPageLoad';
import authContext from '../context/auth/authContext';
import { useContentContext } from '../context/content/contentContext';
import { TiledBackgroundImage } from '../components/decoration/TiledBackgroundImage';
import { ConnectButton } from '@mysten/dapp-kit-react/ui';
import { useCurrentAccount } from '@mysten/dapp-kit-react';
import styled from 'styled-components';

const WalletSection = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: 1.5rem;
  padding: 1rem;
  border-radius: 1rem;
  background-color: ${(props) => props.theme.colors.lightestBg};
`;

const Divider = styled.div`
  display: flex;
  align-items: center;
  margin: 1rem 0;
  width: 100%;

  &::before,
  &::after {
    content: '';
    flex: 1;
    border-bottom: 1px solid ${(props) => props.theme.colors.darkBg};
  }

  span {
    padding: 0 1rem;
    color: ${(props) => props.theme.colors.fontColorDarkLighter};
    font-size: 0.9rem;
  }
`;

const LoginPage: React.FC = () => {
  const { getLocalizedString } = useContentContext();
  const { login, isLoggedIn, connectWallet } = useContext(authContext)!;

  useScrollToTopOnPageLoad();

  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  const currentAccount = useCurrentAccount();

  // Auto-redirect when wallet is connected
  useEffect(() => {
    if (currentAccount && isLoggedIn) {
      // Navigation handled by the <Navigate> component below
    }
  }, [currentAccount, isLoggedIn]);

  if (isLoggedIn) return <Navigate to="/" />;

  return (
    <RelativeWrapper>
      <TiledBackgroundImage />
      <Container
        fullHeight
        flexDirection="column"
        justifyContent="center"
        alignItems="center"
        padding="6rem 2rem 2rem 2rem"
        contentCenteredMobile
      >
        <Form
          onSubmit={(e) => {
            e.preventDefault();
            const email = emailRef.current?.value;
            const password = passwordRef.current?.value;

            email &&
              password &&
              email.length > 0 &&
              password.length > 0 &&
              login(email, password);
          }}
        >
          <HeadingWithLogo textCentered hideIconOnMobile={false}>
            {getLocalizedString('login_page-header_txt')}
          </HeadingWithLogo>

          <WalletSection>
            <ConnectButton />
          </WalletSection>

          <Divider>
            <span>OR</span>
          </Divider>

          <FormGroup>
            <Label htmlFor="email">
              {getLocalizedString('login_page-email_lbl_txt')}
            </Label>
            <Input
              type="email"
              name="email"
              ref={emailRef}
              required
              autoComplete="email"
            />
          </FormGroup>
          <FormGroup>
            <Label htmlFor="password">
              {getLocalizedString('login_page-password_lbl_txt')}
            </Label>
            <ShowPasswordButton passwordRef={passwordRef} />
            <Input
              type="password"
              name="password"
              ref={passwordRef}
              autoComplete="current-password"
              required
            />
          </FormGroup>
          <ButtonGroup>
            <Button primary type="submit" fullWidth>
              {getLocalizedString('login_page-cta_btn_txt')}
            </Button>
            <Link to="/register">
              {getLocalizedString('login_page-no_account_txt')}
            </Link>
          </ButtonGroup>
        </Form>
      </Container>
    </RelativeWrapper>
  );
};

export default LoginPage;
