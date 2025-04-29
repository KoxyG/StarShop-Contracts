use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ValidationError {
    AuctionNameCannotBeEmpty = 101,
    AuctionDescriptionCannotBeEmpty = 102,
    StartingPriceCannotBeZero = 104,
    BidCountMustBeGreaterThanZero = 105,
    TargetPriceMustBeGreaterThanZero = 106,
    InactivitySecondsMustBeGreaterThanZero = 107,
    SequenceNumberMustBeGreaterThanZero = 108,
    MinimumParticipantsMustBeGreaterThanZero = 109,
    EndTimeInPast = 111,
    DutchAuctionFloorPriceMustBeGreaterThanZero = 112,
    MaximumParticipantsMustBeGreaterThanZero = 113,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AuctionError {
    AuctionNotFound = 201,
    AuctionCanceled = 202,
    AuctionCompleted = 203,
    CannotCancelAuction = 204,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ConditionError {
    MaxBidCountReached = 301,
    TargetPriceReached = 302,
    AuctionCompleted = 303,
    MaxInactivitySecondsExceeded = 304,
    TargetSequenceNumberReached = 305,
    MaxNumParticipantsReached = 306,
    BidMustBeHigherThanMaxBid = 307,
    BidMustBeHigherThanStartingPrice = 308,
    BidMustBeLowerThanMaxBid = 309,
    BidMustBeLowerThanStartingPrice = 310,
    DutchBidAlreadyRegistered = 311,
    BidMustMatchDutchPrice = 312,
    AuctionEnded = 313,
    AuctionNotEnded = 314,
    MaxBidCountNotReached = 315,
    TargetPriceNotReached = 316,
    MaxInactivitySecondsNotReached = 317,
    TargetSequenceNumberNotReached = 318,
    MinNumParticipantsNotReached = 319,
    MaxNumParticipantsNotReached = 320,
    NoBidsRegisteredYet = 321,
}
