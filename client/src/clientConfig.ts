interface Config {
  isProduction: boolean;
  contentfulSpaceId: string | undefined;
  contentfulAccessToken: string | undefined;
  googleAnalyticsTrackingId: string | undefined;
  socketURI: string;
}

const config: Config = {
  isProduction: import.meta.env.PROD,
  contentfulSpaceId: import.meta.env.VITE_CONTENTFUL_SPACE_ID,
  contentfulAccessToken: import.meta.env.VITE_CONTENTFUL_ACCESS_TOKEN,
  googleAnalyticsTrackingId: import.meta.env.VITE_GOOGLE_ANALYTICS_TRACKING_ID,
  socketURI: import.meta.env.PROD
    ? import.meta.env.VITE_SERVER_URI
    : `http://${window.location.hostname}:9001/`,
};

export default config;
