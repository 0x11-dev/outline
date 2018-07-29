// @flow
import * as React from 'react';
import { CardElement, injectStripe } from 'react-stripe-elements';
import styled from 'styled-components';
import invariant from 'invariant';
import Button from 'components/Button';

type Props = {
  onSuccess: string => Promise<*>,
  theme: Object,
  stripe?: {
    createToken: () => *,
  },
};

@injectStripe
class CardInputForm extends React.Component<Props> {
  handleSubmit = async (ev: SyntheticEvent<>) => {
    ev.preventDefault();
    invariant(this.props.stripe, 'Stripe must exist');

    try {
      const res = await this.props.stripe.createToken();
      invariant(res, 'res is available');
      const { token, error } = res;

      if (token) {
        this.props.onSuccess(token.id);
      } else {
        alert(error);
      }
    } catch (e) {
      console.error(e);
    }
  };

  render() {
    const { theme } = this.props;
    const style = {
      base: {
        color: theme.text,
        '::placeholder': {
          color: theme.placeholder,
        },
      },
    };

    return (
      <form onSubmit={this.handleSubmit}>
        <StyledCardElement style={style} />
        <Button type="submit">Subscribe</Button>
      </form>
    );
  }
}

const StyledCardElement = styled(CardElement)`
  padding: 8px 12px;
  border-width: 1px;
  border-style: solid;
  border-color: ${props => props.theme.slateLight};
  border-radius: 4px;
  margin: 0 0 16px;
`;

export default CardInputForm;
