pub fn contains_pattern(payload:&[u8],pattern:&[u8])->bool{!pattern.is_empty()&&payload.windows(pattern.len()).any(|w|w==pattern)}
