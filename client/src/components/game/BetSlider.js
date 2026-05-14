import React from 'react';
import { BetSliderInput } from './BetSliderInput';
import { BetSliderWrapper } from './BetSliderWrapper';

export const BetSlider = ({ currentTable, seatId, bet, setBet }) => (
  <BetSliderWrapper>
    <BetSliderInput
      type="range"
      style={{ width: '100%' }}
      step="10"
      min={Math.max(currentTable.minRaise - (currentTable.seats[seatId]?.bet || 0), 0)}
      max={
        currentTable &&
        currentTable.seats &&
        currentTable.seats[seatId].stack &&
        (currentTable.seats[seatId].stack < currentTable.limit
          ? currentTable.seats[seatId].stack
          : currentTable.limit)
      }
      value={bet}
      onChange={(e) => setBet(+e.target.value)}
    />
  </BetSliderWrapper>
);
