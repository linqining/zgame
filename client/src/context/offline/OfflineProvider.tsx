import React from 'react';
import OfflineContext from './offlineContext';
import useServiceWorker from '../../hooks/useServiceWorker';
import { useModalContext } from '../modal/modalContext';
import Text from '../../components/typography/Text';
import { useContentContext } from '../content/contentContext';

interface OfflineProviderProps {
  children: React.ReactNode;
}

const OfflineProvider: React.FC<OfflineProviderProps> = ({ children }) => {
  const { openModal } = useModalContext();
  const { getLocalizedString } = useContentContext();

  const [updateServiceWorker] = useServiceWorker(() => onUpdateServiceWorker());

  const onUpdateServiceWorker = () => {
    openModal(
      () => (
        <Text>{getLocalizedString('service_worker-update_available')}</Text>
      ),
      getLocalizedString('service_worker-update_headline'),
      getLocalizedString('service_worker-update_confirm_btn_txt'),
      updateServiceWorker,
    );
  };

  return <OfflineContext.Provider value={{}}>{children}</OfflineContext.Provider>;
};

export default OfflineProvider;
