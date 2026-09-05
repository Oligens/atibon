pub fn bft_quorum(votes:usize,byzantine_faults:usize)->bool{votes>=2*byzantine_faults+1}
