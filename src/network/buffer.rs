//! Buffer pool for reducing allocations in packet handling.
//!
//! Pre-allocates a pool of buffers that can be reused across
//! packet operations to minimize heap allocations in the hot path.

use std::sync::Arc;

use parking_lot::Mutex;

/// Maximum size for a DNS packet buffer.
/// Ethernet (14) + IPv6 (40) + UDP (8) + DNS (512) = 574
/// We round up to 1024 for safety and future expansion.
pub const MAX_PACKET_SIZE: usize = 1024;

/// A reusable buffer from the pool.
pub struct PooledBuffer {
    data: Vec<u8>,
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PooledBuffer {
    /// Get a mutable slice of the buffer.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get an immutable slice of the buffer.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Resize the buffer (within `MAX_PACKET_SIZE`).
    #[inline]
    pub fn resize(&mut self, len: usize) {
        debug_assert!(len <= MAX_PACKET_SIZE);
        self.data.resize(len, 0);
    }

    /// Clear the buffer.
    #[inline]
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Get the length of the data in the buffer.
    #[inline]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Return the buffer to the pool
        let mut buffer = std::mem::take(&mut self.data);
        buffer.clear();
        if buffer.capacity() <= MAX_PACKET_SIZE * 2 {
            // Only return reasonably-sized buffers
            self.pool.lock().push(buffer);
        }
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for PooledBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

/// A pool of reusable buffers for packet construction.
///
/// This reduces allocation pressure by reusing buffers across
/// multiple packet operations.
#[derive(Clone)]
pub struct BufferPool {
    buffers: Arc<Mutex<Vec<Vec<u8>>>>,
    initial_capacity: usize,
}

impl BufferPool {
    /// Create a new buffer pool with the specified number of pre-allocated buffers.
    pub fn new(pool_size: usize) -> Self {
        let buffers: Vec<Vec<u8>> = (0..pool_size)
            .map(|_| Vec::with_capacity(MAX_PACKET_SIZE))
            .collect();

        Self {
            buffers: Arc::new(Mutex::new(buffers)),
            initial_capacity: pool_size,
        }
    }

    /// Get a buffer from the pool.
    ///
    /// If the pool is empty, a new buffer is allocated.
    /// The returned `PooledBuffer` will be returned to the pool when dropped.
    pub fn get(&self) -> PooledBuffer {
        let data = self.buffers.lock().pop().unwrap_or_else(|| {
            // Pool exhausted, allocate a new buffer
            Vec::with_capacity(MAX_PACKET_SIZE)
        });

        PooledBuffer {
            data,
            pool: Arc::clone(&self.buffers),
        }
    }

    /// Get a buffer pre-filled with zeros of the specified length.
    pub fn get_zeroed(&self, len: usize) -> PooledBuffer {
        let mut buffer = self.get();
        buffer.data.resize(len, 0);
        buffer
    }

    /// Returns the current number of available buffers in the pool.
    pub fn available(&self) -> usize {
        self.buffers.lock().len()
    }

    /// Returns the initial pool capacity.
    pub const fn capacity(&self) -> usize {
        self.initial_capacity
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_get_and_return_buffers_to_pool() {
        let pool = BufferPool::new(4);
        assert_eq!(pool.available(), 4);

        let buf1 = pool.get();
        assert_eq!(pool.available(), 3);

        let buf2 = pool.get();
        assert_eq!(pool.available(), 2);

        drop(buf1);
        assert_eq!(pool.available(), 3);

        drop(buf2);
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn should_allocate_new_buffer_when_pool_exhausted() {
        let pool = BufferPool::new(2);

        let _buf1 = pool.get();
        let _buf2 = pool.get();
        assert_eq!(pool.available(), 0);

        // Should still work, just allocates a new buffer
        let _buf3 = pool.get();
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn should_support_resize_and_clear_operations() {
        let pool = BufferPool::new(1);
        let mut buf = pool.get();

        assert!(buf.is_empty());

        buf.resize(100);
        assert_eq!(buf.len(), 100);

        buf.as_mut_slice()[0] = 42;
        assert_eq!(buf.as_slice()[0], 42);

        buf.clear();
        assert!(buf.is_empty());
    }

    #[test]
    fn should_return_zeroed_buffer_of_specified_length() {
        let pool = BufferPool::new(1);
        let buf = pool.get_zeroed(50);

        assert_eq!(buf.len(), 50);
        assert!(buf.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn should_share_underlying_pool_when_cloned() {
        let pool1 = BufferPool::new(4);
        let pool2 = pool1.clone();

        // Both should share the same underlying pool
        let _buf = pool1.get();
        assert_eq!(pool2.available(), 3);
    }
}
