import { createAsyncThunk, createSlice } from '@reduxjs/toolkit'
import { api } from '../lib/api'

// Initial session check: the httpOnly cookie may already hold a valid session
// from a previous visit — ask the server who we are.
export const fetchMe = createAsyncThunk('auth/fetchMe', () => api.me())

export const login = createAsyncThunk(
  'auth/login',
  async ({ email, password }, { rejectWithValue }) => {
    try {
      await api.login(email, password)
      // Login response is minimal — fetch full identity (roles, permissions).
      return await api.me()
    } catch (err) {
      return rejectWithValue({ status: err.status, message: err.message })
    }
  }
)

export const logout = createAsyncThunk('auth/logout', () => api.logout())

const authSlice = createSlice({
  name: 'auth',
  initialState: {
    user: null, // identity from /api/auth/me, or null
    checking: true, // true until the initial fetchMe settles
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchMe.fulfilled, (state, action) => {
        state.user = action.payload
        state.checking = false
      })
      .addCase(fetchMe.rejected, (state) => {
        state.user = null
        state.checking = false
      })
      .addCase(login.fulfilled, (state, action) => {
        state.user = action.payload
      })
      // Clear identity even if the server call failed — the server deletes
      // the session row on its side; locally we always drop to signed-out.
      .addCase(logout.fulfilled, (state) => {
        state.user = null
      })
      .addCase(logout.rejected, (state) => {
        state.user = null
      })
  },
})

export const selectUser = (state) => state.auth.user
export const selectAuthChecking = (state) => state.auth.checking

export default authSlice.reducer
