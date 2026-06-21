import React, { useContext } from 'react';
import styled from 'styled-components';
import contentContext from '../../context/content/contentContext';
import ChipsAmountPill from './ChipsAmountPill';
import { InfoPill } from './InfoPill';
import { Table, Card } from '../../types/game';

interface GameStateInfoProps {
  currentTable: Table;
  communityCards?: Card[];
}

const Wrapper = styled.div`
  display: grid;
  grid-gap: 0.5rem;
  grid-template-columns: repeat(4, auto);
  justify-content: center;
  justify-items: center;
  align-items: center;
  width: 100%;
`;

export const GameStateInfo: React.FC<GameStateInfoProps> = ({ currentTable, communityCards }) => {
  const { getLocalizedString } = useContext(contentContext)!;
  const boardLen = communityCards?.length ?? currentTable.board.length;

  return (
    <Wrapper>
      {currentTable.players.length <= 1 || currentTable.handOver ? (
        <InfoPill>{getLocalizedString('game_state-info_wait')}</InfoPill>
      ) : (
        <InfoPill>
          {boardLen === 0 && getLocalizedString('game_state-info_pre-flop')}
          {boardLen === 3 && getLocalizedString('game_state-info_flop')}
          {boardLen === 4 && getLocalizedString('game_state-info_turn')}
          {boardLen === 5 && getLocalizedString('game_state-info_river')}
          {currentTable.wentToShowdown && getLocalizedString('game_state-info_showdown')}
        </InfoPill>
      )}

      {!!currentTable.mainPot && (
        <ChipsAmountPill
          chipsAmount={currentTable.mainPot}
          style={{ minWidth: '150px' }}
        />
      )}

      {currentTable.sidePots.length > 0 &&
        currentTable.sidePots.map((sidePot, index) => (
          <ChipsAmountPill
            key={index}
            chipsAmount={sidePot.amount}
            style={{ minWidth: '150px' }}
          />
        ))}
    </Wrapper>
  );
};
