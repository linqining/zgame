import { createContext, useContext } from 'react';

export interface GlobalContextType {
  isLoading: boolean;
  setIsLoading: React.Dispatch<React.SetStateAction<boolean>>;
  id: string | null;
  setId: React.Dispatch<React.SetStateAction<string | null>>;
  userName: string | null;
  setUserName: React.Dispatch<React.SetStateAction<string | null>>;
  email: string | null;
  setEmail: React.Dispatch<React.SetStateAction<string | null>>;
  chipsAmount: number | null;
  setChipsAmount: React.Dispatch<React.SetStateAction<number | null>>;
  tables: unknown[] | null;
  setTables: React.Dispatch<React.SetStateAction<unknown[] | null>>;
  players: unknown[] | null;
  setPlayers: React.Dispatch<React.SetStateAction<unknown[] | null>>;
}

const globalContext = createContext<GlobalContextType | undefined>(undefined);

export const useGlobalContext = (): GlobalContextType => {
  const context = useContext(globalContext);
  if (context === undefined) {
    throw new Error('useGlobalContext must be used within a GlobalState');
  }
  return context;
};

export default globalContext;
