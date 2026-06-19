import React, { useContext } from 'react';
import { Link } from 'react-router-dom';
import styled from 'styled-components';
import Text from '../typography/Text';
import ColoredText from '../typography/ColoredText';
import contentContext, { StaticPage } from '../../context/content/contentContext';

interface FooterProps {
  className?: string;
  setLang: (lang: string) => void;
  staticPages: StaticPage[] | null;
  variant?: 'light' | 'dark';
}

const StyledFooter = styled.footer`
  text-align: center;
  padding: 2rem 0;
  font-size: 1rem;
  background-color: ${(props: any) => props.theme.colors.lightestBg};
  border-top: 1px solid rgba(226, 232, 240, 0.9);
`;

const FooterText = styled(Text)`
  a {
    /* TODO: #475569 提取到 theme */
    color: #475569;
    transition: all 0.2s ease;
    &:hover {
      color: ${({ theme }) => theme.colors.secondaryCta};
    }
  }
`;

const Footer: React.FC<FooterProps> = ({ className, setLang, staticPages }) => {
  const { getLocalizedString } = useContext(contentContext)!;

  return (
    <StyledFooter className={className}>
      <FooterText textAlign="center" fontSize="0.9rem">
        {getLocalizedString('footer-lang_selection_txt')}:{'  '}
        <a
          href="!"
          onClick={(e) => {
            e.preventDefault();
            setLang('en');
          }}
        >
          EN
        </a>{' '}
        |{' '}
        <a
          href="!"
          onClick={(e) => {
            e.preventDefault();
            setLang('zh');
          }}
        >
          中文
        </a>{' '}
        |{' '}
        <a
          href="!"
          onClick={(e) => {
            e.preventDefault();
            setLang('de');
          }}
        >
          DE
        </a>
      </FooterText>
      <Text textAlign="center" fontSize="0.9rem">
        {staticPages &&
          staticPages.map((page, index, array) => {
            const component = (
              <Link key={page.slug} to={`/${page.slug}`} style={{ color: '#475569' }}>
                {page.title}
              </Link>
            );
            if (index < array.length - 1)
              return (
                <span key={page.slug}>
                  {component}
                  {' | '}
                </span>
              );
            else return component;
          })}
      </Text>
      <Text textAlign="center" fontSize="0.9rem">
        <ColoredText>{getLocalizedString('footer-copyright_txt')}</ColoredText>
      </Text>
    </StyledFooter>
  );
};

export default Footer;
