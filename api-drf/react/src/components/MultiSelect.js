import styled from '@emotion/styled';

export const MultiSelectContainer = styled.div`
  & .multi-select__menu {
    background-color: var(--light);
    border: 1px solid rgba(255, 255, 255, 0.09);
    border-radius: 0;

    & > * {
      padding-top: 0;
      padding-bottom: 0;
    }
    
    & .multi-select__option {
      background-color: #34353e;
      padding-top: 0.25rem;
      padding-bottom: 0.25rem;
      border: 2px solid #34353e;
      color: white;
    }

    & .multi-select__option--is-focused {
      background-color: var(--info);
      border: 2px solid black;
    }
  }

  & .multi-select__control {
    background-color: rgba(255, 255, 255, 0.05);
    border-color: rgba(255, 255, 255, 0.09);
    color: rgba(255, 255, 255, 0.87);

    & .multi-select__indicator-separator {
      background-color: var(--light);
    }

    & .multi-select__value-container {
      padding-top: 0;
      padding-bottom: 0;
    }

    & .multi-select__input {
      color: var(--light) !important;
    }

    & .multi-select__indicator {
      padding-left: 0;
      padding-right: 0;

      & svg {
        width: 16px;
        height: 16px;
      }

      &.multi-select__clear-indicator:hover {
        color: var(--danger);
      }
    }

    &:hover {
      border-color: rgba(255, 255, 255, 0.09);
    }

    & .multi-select__multi-value {
      background-color: var(--secondary);

      & .multi-select__multi-value__label {
        background-color: rgba(255, 255, 255, 0.02);
        color: var(--text-light);

        &:hover {
          background-color: rgba(255, 255, 255, 0.09);
        }
      }
   
      & .multi-select__multi-value__remove {
        background-color: rgba(255, 255, 255, 0.02);
        color: var(--text-light);

        &:hover {
          background-color: var(--danger);
        }
      }
    }
  }
`;

