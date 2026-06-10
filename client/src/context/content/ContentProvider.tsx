import React, { useState, useEffect } from 'react';
import ContentContext, { ContentContextType } from './contentContext';
import useContentful from '../../hooks/useContentful';
import { useLocaContext } from '../localization/locaContext';

import en from '../localization/locales/en.json';
import zh from '../localization/locales/zh.json';
import de from '../localization/locales/de.json';

const localTranslations: Record<string, Record<string, string>> = { en, zh, de };

interface ContentProviderProps {
  children: React.ReactNode;
}

const ContentProvider: React.FC<ContentProviderProps> = ({ children }) => {
  const { lang } = useLocaContext();
  const contentfulClient = useContentful();

  const [isLoading, setIsLoading] = useState(true);
  const [staticPages, setStaticPages] = useState<ContentContextType['staticPages']>(null);
  const [localizedStrings, setLocalizedStrings] = useState<Record<string, string> | null>(null);

  useEffect(() => {
    setIsLoading(true);

    fetchContent();

    setIsLoading(false);
    // eslint-disable-next-line
  }, [lang]);

  const fetchContent = () => {
    if (!contentfulClient) {
      setIsLoading(false);
      return;
    }

    contentfulClient
      .getEntries({ content_type: 'key', locale: lang })
      .then((res) => {
        const localizedStrings: Record<string, string> = {};

        res.items.forEach(
          (item) =>
            (localizedStrings[(item.fields as { keyName: string }).keyName] =
              (item.fields as { value: { fields: { value: string } } }).value.fields.value),
        );

        setLocalizedStrings(localizedStrings);
      })
      .catch(() => {
        setLocalizedStrings({});
      });

    contentfulClient
      .getEntries({ content_type: 'staticPage', locale: lang })
      .then((res) => {
        setStaticPages(
          res.items.map((item) => {
            const fields = item.fields as { slug: string; title: string; content: { fields: { value: string } } };
            return {
              slug: fields.slug,
              title: fields.title,
              content: fields.content.fields.value,
            };
          }),
        );
      });
  };

  const getLocalizedString = (key: string): string => {
    if (localizedStrings && localizedStrings[key]) {
      return localizedStrings[key];
    }
    const localDict = localTranslations[lang] || localTranslations['en'];
    if (localDict && localDict[key]) {
      return localDict[key];
    }
    return key;
  };

  return (
    <ContentContext.Provider
      value={{ isLoading, staticPages, getLocalizedString }}
    >
      {children}
    </ContentContext.Provider>
  );
};

export default ContentProvider;
