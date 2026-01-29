use crate::layer1::block::Block;
use crate::layer1::world_state::WorldStateTrie;
use anyhow::Result;

pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub state: WorldStateTrie,
}

impl Blockchain {
    pub fn new() -> Self {
        Self {
            blocks: vec![],
            state: WorldStateTrie::new(),
        }
    }

    pub fn add_block(&mut self, mut block: Block) -> Result<()> {
        // Validate block
        if let Some(parent) = self.blocks.last() {
            block.header_validity_check(parent)?;
        } else {
            // Genesis block
            if block.header.number != 0 {
                return Err(anyhow::anyhow!("First block must be genesis block (number 0)"));
            }
        }

        // Update state root in block header
        block.header.state_root = self.state.root_hash();

        // Validate holistic validity
        block.holistic_validity_check(&self.state)?;

        // Add block to chain
        self.blocks.push(block);

        Ok(())
    }

    pub fn get_latest_block(&self) -> Option<&Block> {
        self.blocks.last()
    }
}

