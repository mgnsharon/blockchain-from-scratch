//! The automated teller machine gives you cash after you swipe your card and enter your pin.
//! The atm may fail to give you cash if it is empty or you haven't swiped your card, or you have
//! entered the wrong pin.

use super::StateMachine;

/// The keys on the ATM keypad
#[derive(Hash, Debug, PartialEq, Eq, Clone)]
pub enum Key {
	One,
	Two,
	Three,
	Four,
	Enter,
}

/// Something you can do to the ATM
pub enum Action {
	/// Swipe your card at the ATM. The attached value is the hash of the pin
	/// that should be keyed in on the keypad next.
	SwipeCard(u64),
	/// Press a key on the keypad
	PressKey(Key),
}

/// The various states of authentication possible with the ATM
#[derive(Debug, PartialEq, Eq, Clone)]
enum Auth {
	/// No session has begun yet. Waiting for the user to swipe their card
	Waiting,
	/// The user has swiped their card, providing the enclosed PIN hash.
	/// Waiting for the user to key in their pin
	Authenticating(u64),
	/// The user has authenticated. Waiting for them to key in the amount
	/// of cash to withdraw
	Authenticated,
}

/// The ATM. When a card is swiped, the ATM learns the correct pin's hash.
/// It waits for you to key in your pin. You can press as many numeric keys as
/// you like followed by enter. If the pin is incorrect, your card is returned
/// and the ATM automatically goes back to the main menu. If your pin is correct,
/// the ATM waits for you to key in an amount of money to withdraw. Withdraws
/// are bounded only by the cash in the machine (there is no account balance).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Atm {
	/// How much money is in the ATM
	cash_inside: u64,
	/// The machine's authentication status.
	expected_pin_hash: Auth,
	/// All the keys that have been pressed since the last `Enter`
	keystroke_register: Vec<Key>,
}

impl StateMachine for Atm {
	// Notice that we are using the same type for the state as we are using for the machine this
	// time.
	type State = Self;
	type Transition = Action;

	fn next_state(starting_state: &Self::State, t: &Self::Transition) -> Self::State {
		match t {
			Action::PressKey(key) => match starting_state.expected_pin_hash {
				Auth::Waiting => Atm {
					cash_inside: starting_state.cash_inside,
					expected_pin_hash: Auth::Waiting,
					keystroke_register: vec![],
				},
				Auth::Authenticating(pin) => {
					let mut atm = Atm {
						cash_inside: starting_state.cash_inside,
						expected_pin_hash: starting_state.expected_pin_hash.clone(),
						keystroke_register: starting_state.keystroke_register.clone(),
					};
					match key {
						Key::One => {
							atm.keystroke_register.push(Key::One);
							atm
						},
						Key::Two => {
							atm.keystroke_register.push(Key::Two);
							atm
						},
						Key::Three => {
							atm.keystroke_register.push(Key::Three);
							atm
						},
						Key::Four => {
							atm.keystroke_register.push(Key::Four);
							atm
						},
						Key::Enter => {
							let entered_pin = crate::hash(&atm.keystroke_register);
							if pin == entered_pin {
								atm.expected_pin_hash = Auth::Authenticated;
							} else {
								atm.expected_pin_hash = Auth::Waiting;
							}
							atm.keystroke_register = vec![];
							atm
						},
					}
				},
				Auth::Authenticated => {
					let mut atm = Atm {
						cash_inside: starting_state.cash_inside,
						expected_pin_hash: starting_state.expected_pin_hash.clone(),
						keystroke_register: starting_state.keystroke_register.clone(),
					};
					match key {
						Key::One => {
							atm.keystroke_register.push(Key::One);
							atm
						},
						Key::Two => {
							atm.keystroke_register.push(Key::Two);
							atm
						},
						Key::Three => {
							atm.keystroke_register.push(Key::Three);
							atm
						},
						Key::Four => {
							atm.keystroke_register.push(Key::Four);
							atm
						},
						Key::Enter => {
							let amount: u64 =
								atm.keystroke_register.iter().fold(0, |acc, key| match key {
									Key::One => format!("{}1", acc).parse::<u64>().unwrap(),
									Key::Two => format!("{}2", acc).parse::<u64>().unwrap(),
									Key::Three => format!("{}3", acc).parse::<u64>().unwrap(),
									Key::Four => format!("{}4", acc).parse::<u64>().unwrap(),
									_ => acc,
								});
							atm.cash_inside = if atm.cash_inside >= amount {
								atm.cash_inside - amount
							} else {
								atm.cash_inside
							};
							atm.keystroke_register = vec![];
							atm.expected_pin_hash = Auth::Waiting;
							atm
						},
					}
				},
			},
			Action::SwipeCard(pin) => match starting_state.expected_pin_hash {
				Auth::Waiting => Atm {
					cash_inside: starting_state.cash_inside,
					expected_pin_hash: Auth::Authenticating(*pin),
					keystroke_register: vec![],
				},
				Auth::Authenticating(_pin) => Atm {
					cash_inside: starting_state.cash_inside,
					expected_pin_hash: starting_state.expected_pin_hash.clone(),
					keystroke_register: starting_state.keystroke_register.clone(),
				},
				Auth::Authenticated => Atm {
					cash_inside: starting_state.cash_inside,
					expected_pin_hash: Auth::Authenticated,
					keystroke_register: vec![],
				},
			},
		}
	}
}

#[test]
fn sm_3_simple_swipe_card() {
	let start =
		Atm { cash_inside: 10, expected_pin_hash: Auth::Waiting, keystroke_register: Vec::new() };
	let end = Atm::next_state(&start, &Action::SwipeCard(1234));
	let expected = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(1234),
		keystroke_register: Vec::new(),
	};

	assert_eq!(end, expected);
}

#[test]
fn sm_3_swipe_card_again_part_way_through() {
	let start = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(1234),
		keystroke_register: Vec::new(),
	};
	let end = Atm::next_state(&start, &Action::SwipeCard(1234));
	let expected = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(1234),
		keystroke_register: Vec::new(),
	};

	assert_eq!(end, expected);

	let start = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(1234),
		keystroke_register: vec![Key::One, Key::Three],
	};
	let end = Atm::next_state(&start, &Action::SwipeCard(1234));
	let expected = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(1234),
		keystroke_register: vec![Key::One, Key::Three],
	};

	assert_eq!(end, expected);
}

#[test]
fn sm_3_press_key_before_card_swipe() {
	let start =
		Atm { cash_inside: 10, expected_pin_hash: Auth::Waiting, keystroke_register: Vec::new() };
	let end = Atm::next_state(&start, &Action::PressKey(Key::One));
	let expected =
		Atm { cash_inside: 10, expected_pin_hash: Auth::Waiting, keystroke_register: Vec::new() };

	assert_eq!(end, expected);
}

#[test]
fn sm_3_enter_single_digit_of_pin() {
	let start = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(1234),
		keystroke_register: Vec::new(),
	};
	let end = Atm::next_state(&start, &Action::PressKey(Key::One));
	let expected = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(1234),
		keystroke_register: vec![Key::One],
	};

	assert_eq!(end, expected);

	let start = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(1234),
		keystroke_register: vec![Key::One],
	};
	let end1 = Atm::next_state(&start, &Action::PressKey(Key::Two));
	let expected1 = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(1234),
		keystroke_register: vec![Key::One, Key::Two],
	};

	assert_eq!(end1, expected1);
}

#[test]
fn sm_3_enter_wrong_pin() {
	// Create hash of pin
	let pin = vec![Key::One, Key::Two, Key::Three, Key::Four];
	let pin_hash = crate::hash(&pin);

	let start = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(pin_hash),
		keystroke_register: vec![Key::Three, Key::Three, Key::Three, Key::Three],
	};
	let end = Atm::next_state(&start, &Action::PressKey(Key::Enter));
	let expected =
		Atm { cash_inside: 10, expected_pin_hash: Auth::Waiting, keystroke_register: Vec::new() };

	assert_eq!(end, expected);
}

#[test]
fn sm_3_enter_correct_pin() {
	// Create hash of pin
	let pin = vec![Key::One, Key::Two, Key::Three, Key::Four];
	let pin_hash = crate::hash(&pin);

	let start = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticating(pin_hash),
		keystroke_register: vec![Key::One, Key::Two, Key::Three, Key::Four],
	};
	let end = Atm::next_state(&start, &Action::PressKey(Key::Enter));
	let expected = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticated,
		keystroke_register: Vec::new(),
	};

	assert_eq!(end, expected);
}

#[test]
fn sm_3_enter_single_digit_of_withdraw_amount() {
	let start = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticated,
		keystroke_register: Vec::new(),
	};
	let end = Atm::next_state(&start, &Action::PressKey(Key::One));
	let expected = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticated,
		keystroke_register: vec![Key::One],
	};

	assert_eq!(end, expected);

	let start = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticated,
		keystroke_register: vec![Key::One],
	};
	let end1 = Atm::next_state(&start, &Action::PressKey(Key::Four));
	let expected1 = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticated,
		keystroke_register: vec![Key::One, Key::Four],
	};

	assert_eq!(end1, expected1);
}

#[test]
fn sm_3_try_to_withdraw_too_much() {
	let start = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticated,
		keystroke_register: vec![Key::One, Key::Four],
	};
	let end = Atm::next_state(&start, &Action::PressKey(Key::Enter));
	let expected =
		Atm { cash_inside: 10, expected_pin_hash: Auth::Waiting, keystroke_register: Vec::new() };

	assert_eq!(end, expected);
}

#[test]
fn sm_3_withdraw_acceptable_amount() {
	let start = Atm {
		cash_inside: 10,
		expected_pin_hash: Auth::Authenticated,
		keystroke_register: vec![Key::One],
	};
	let end = Atm::next_state(&start, &Action::PressKey(Key::Enter));
	let expected =
		Atm { cash_inside: 9, expected_pin_hash: Auth::Waiting, keystroke_register: Vec::new() };

	assert_eq!(end, expected);
}
