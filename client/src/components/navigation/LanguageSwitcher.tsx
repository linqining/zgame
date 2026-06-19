import React from 'react';
import styled from 'styled-components';
import { useLocaContext } from '../../context/localization/locaContext';

const languages = [
  { code: 'en', label: 'EN' },
  { code: 'zh', label: 'ZH' },
  { code: 'de', label: 'DE' },
];

const LangSwitcherWrap = styled.div`
  display: inline-flex;
  align-items: center;
  gap: 0.15rem;
  padding: 0.2rem;
  background: rgba(241, 245, 249, 0.8);
  border: 1px solid rgba(226, 232, 240, 0.9);
  border-radius: 8px;
`;

const LangOption = styled.button<{ $active: boolean }>`
  border: none;
  /* TODO: #764ba2 提取到 theme */
  background: ${({ $active, theme }) =>
    $active ? `linear-gradient(135deg, ${theme.colors.secondaryCta}, #764ba2)` : 'transparent'};
  /* TODO: #475569 提取到 theme */
  color: ${({ $active, theme }) => ($active ? theme.colors.lightestBg : '#475569')};
  cursor: pointer;
  padding: 0.3rem 0.55rem;
  border-radius: 6px;
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 0.78rem;
  font-weight: 600;
  line-height: 1;
  transition: all 0.2s ease;

  &:hover {
    color: ${({ $active, theme }) => ($active ? theme.colors.lightestBg : theme.colors.secondaryCta)};
  }

  &:focus {
    outline: none;
  }
`;

const LanguageSwitcher: React.FC = () => {
  const { lang, setLang } = useLocaContext();
  return (
    <LangSwitcherWrap role="group" aria-label="Language switcher">
      {languages.map((l) => (
        <LangOption
          key={l.code}
          $active={lang === l.code}
          onClick={() => setLang(l.code)}
          aria-pressed={lang === l.code}
        >
          {l.label}
        </LangOption>
      ))}
    </LangSwitcherWrap>
  );
};

export default LanguageSwitcher;
