import React, { useState, useEffect, useContext } from 'react';
import ContentContext from './contentContext';
import useContentful from '../../hooks/useContentful';
import locaContext from '../localization/locaContext';

import en from '../localization/locales/en.json';
import zh from '../localization/locales/zh.json';
import de from '../localization/locales/de.json';

const localTranslations = { en, zh, de };

const ContentProvider = ({ children }) => {
  const { lang } = useContext(locaContext);
  const contentfulClient = useContentful();

  const [isLoading, setIsLoading] = useState(true);
  const [staticPages, setStaticPages] = useState(null);
  const [localizedStrings, setLocalizedStrings] = useState(null);

  useEffect(() => {
    setIsLoading(true);

    fetchContent();

    setIsLoading(false);
    // eslint-disable-next-line
  }, [lang]);

  const fetchContent = () => {
    contentfulClient
      .getEntries({ content_type: 'key', locale: lang })
      .then((res) => {
        let localizedStrings = {};

        res.items.forEach(
          (item) =>
            (localizedStrings[item.fields.keyName] =
              item.fields.value.fields.value),
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
          res.items.map((item) => ({
            slug: item.fields.slug,
            title: item.fields.title,
            content: item.fields.content.fields.value,
          })),
        );
      });
  };

  const getLocalizedString = (key) => {
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
