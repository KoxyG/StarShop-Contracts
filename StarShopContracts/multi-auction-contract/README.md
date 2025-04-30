# 🧮 Multi-Condition Auction Contract

A powerful, customizable auction smart contract built for Soroban.  
Supports **Regular**, **Dutch**, and **Reverse** auctions with flexible programmable end conditions.

---

## 🚀 Features

### ✅ Create Auctions

- Auction owners can create auctions with:
  - Metadata: item name, description
  - Token: which asset will be used
  - Auction type: `Regular`, `Dutch`, or `Reverse`
  - Starting price and end time
  - Optional dynamic close conditions

---

## 🎯 Auction Types

| Type        | Description                                                                       |
| ----------- | --------------------------------------------------------------------------------- |
| **Regular** | Classic "highest bid wins" auction. Ends at a time or when special rules are met. |
| **Dutch**   | Starts high, price drops over time. First bidder to accept current price wins.    |
| **Reverse** | Starts at a maximum price; participants submit lower bids. Lowest bid wins.       |

> ✅ You define the logic per auction type with full condition customization.

---

## 📦 Auction Metadata

Each auction contains:

- `title`: name of the item
- `description`: auction purpose or asset info
- `token`: asset being exchanged
- `auction_type`: `Regular`, `Dutch`, or `Reverse`

---

## ⏳ Custom End Conditions (Optional)

You can configure an auction to end based on **any of these criteria**:

| Condition                  | Description                                             |
| -------------------------- | ------------------------------------------------------- |
| `on_bid_count`             | Ends after X number of bids                             |
| `on_target_price`          | Ends when a bid reaches or drops to a price target      |
| `on_inactivity_seconds`    | Ends after no bids for X seconds                        |
| `on_fixed_sequence_number` | Ends after a specific ledger sequence number            |
| `on_minimum_participants`  | Ends after X unique bidders have participated           |
| `on_maximum_participants`  | Ends when the number of bidders reaches a cap           |
| `immediate_accept_offer`   | Ends instantly if a special "Buy Now" price is accepted |

> 🧠 For reverse auctions, `target_price` means **lowest bid target**.

---

## 🧾 Auction Lifecycle

### `create_auction(...)`

- Initializes an auction with selected type and parameters

### `make_bid(...)`

- Validates and processes bids:
  - In **Regular**: higher bids win
  - In **Dutch**: first bidder wins as price falls
  - In **Reverse**: lower bids are better

### `cancel_auction(...)`

- Can be done by the owner if:
  - No bids yet
  - Auction isn't completed or canceled

### `end_auction(...)`

- Ends an auction if:
  - `end_time` passed
  - Or **any special condition** is satisfied
- Transfers funds and marks it completed

---

## 🧠 Reverse Auction Logic Highlights

- Bids **must be lower** than the current bid
- Useful for:
  - Freelance job/task pricing
  - Service offers
  - Product sales with lowest-price wins

---

## 📜 Error Handling

- `AuctionNotFound`
- `AuctionCanceled`
- `AuctionCompleted`
- `TargetPriceNotReached`
- `NoBidsRegisteredYet`
- `MaxBidCountNotReached`
- `BidTooHigh` (Reverse)
- `BidTooLow` (Regular)
- `AuctionNotEnded`

---
