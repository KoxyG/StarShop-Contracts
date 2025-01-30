#![no_std]
use soroban_sdk::contract;

mod alerts;
mod datatype;
mod follow;
mod interface;
mod notification;

#[cfg(test)]
mod test;

#[contract]
pub struct ProductFollowContract;
