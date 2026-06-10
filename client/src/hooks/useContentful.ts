import { createClient, ContentfulClientApi } from 'contentful';
import config from '../clientConfig';

const useContentful = (): ContentfulClientApi | null => {
  if (!config.contentfulSpaceId || !config.contentfulAccessToken) {
    console.warn('[useContentful] Missing spaceId or accessToken, skipping Contentful init');
    return null;
  }
  const client = createClient({
    space: config.contentfulSpaceId,
    accessToken: config.contentfulAccessToken,
  });
  return client;
};

export default useContentful;
