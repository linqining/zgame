import React, { useContext } from 'react';
import { Link } from 'react-router-dom';
import Container from '../components/layout/Container';
import HeadingWithLogo from '../components/typography/HeadingWithLogo';
import Button from '../components/buttons/Button';
import { FormGroup } from '../components/forms/FormGroup';
import { Label } from '../components/forms/Label';
import { Input } from '../components/forms/Input';
import styled from 'styled-components';
import { Form } from '../components/forms/Form';
import RelativeWrapper from '../components/layout/RelativeWrapper';
import { useGlobalContext } from '../context/global/globalContext';
import { useContentContext } from '../context/content/contentContext';

const Wrapper = styled.div`
  display: grid;
  grid-template-columns: 1fr 1fr;
  grid-gap: 2rem;
  margin-bottom: 2rem;

  ${FormGroup} > *~* {
    margin: 0.5rem 0;
  }

  @media screen and (max-width: 624px) {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    width: 100%;
    max-width: 320px;

    ${FormGroup} > *~* {
      margin: 0.5rem 0;
    }
  }
`;

const Dashboard: React.FC = () => {
  const { getLocalizedString } = useContentContext();
  const { userName, email } = useGlobalContext();

  return (
    <RelativeWrapper>
      <Container
        fullHeight
        flexDirection="column"
        justifyContent="center"
        contentCenteredMobile
        alignItems="center"
        padding="6rem 2rem 2rem 2rem"
      >
        <Form onSubmit={(e) => e.preventDefault()}>
          <HeadingWithLogo textCentered hideIconOnMobile={false}>
            {getLocalizedString('dashboard-heading_txt')}
          </HeadingWithLogo>
          <Wrapper>
            <FormGroup>
              <Label>{getLocalizedString('dashboard-nickname_lbl_txt')}</Label>
              <Input value={userName ?? ''} />
              <Button primary>
                {getLocalizedString('dashboard-nickname_btn_txt')}
              </Button>
            </FormGroup>
            <FormGroup>
              <Label>{getLocalizedString('dashboard-email_lbl_txt')}</Label>
              <Input type="email" value={email ?? ''} />
              <Button primary>
                {getLocalizedString('dashboard-email_btn_txt')}
              </Button>
            </FormGroup>
            <FormGroup style={{ gridColumnStart: '1', gridColumnEnd: '3' }}>
              <Button primary>
                {getLocalizedString('dashboard-reset_pw_btn_text')}
              </Button>
              <Button>
                {getLocalizedString('dashboard-delete_acct_btn_text')}
              </Button>
            </FormGroup>
            <Button
              as={Link}
              to="/"
              secondary
              style={{ gridColumnStart: '1', gridColumnEnd: '3' }}
            >
              {getLocalizedString('static_page-back_btn_txt')}
            </Button>
          </Wrapper>
        </Form>
      </Container>
    </RelativeWrapper>
  );
};

export default Dashboard;
