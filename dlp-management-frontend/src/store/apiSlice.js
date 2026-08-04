import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react'
import { clearUser } from './authSlice'

// Server data lives here (RTK Query) — auth/session state stays in authSlice.
// Session rides the httpOnly cookie, so we just send credentials; no tokens
// are handled in JS.
const rawBaseQuery = fetchBaseQuery({ baseUrl: '/api', credentials: 'same-origin' })

// If any call comes back 401, the session is gone — drop to signed-out so the
// route guard sends the user to /login.
const baseQuery = async (args, apiCtx, extra) => {
  const result = await rawBaseQuery(args, apiCtx, extra)
  if (result.error && result.error.status === 401) {
    apiCtx.dispatch(clearUser())
  }
  return result
}

export const apiSlice = createApi({
  reducerPath: 'api',
  baseQuery,
  tagTypes: ['EnrollmentToken', 'Agent', 'User', 'Session', 'Audit', 'ProtectedCollection', 'ProtectedDocument', 'IndexStatus'],
  endpoints: (b) => ({
    // Enrollment tokens
    getEnrollmentTokens: b.query({
      query: () => '/enrollment-tokens',
      providesTags: ['EnrollmentToken'],
    }),
    createEnrollmentToken: b.mutation({
      query: (body) => ({ url: '/enrollment-tokens', method: 'POST', body }),
      invalidatesTags: ['EnrollmentToken'],
    }),
    revokeEnrollmentToken: b.mutation({
      query: (id) => ({ url: `/enrollment-tokens/${id}/revoke`, method: 'POST' }),
      invalidatesTags: ['EnrollmentToken'],
    }),

    // Agents
    getAgents: b.query({
      query: () => '/agents',
      providesTags: ['Agent'],
    }),
    retireAgent: b.mutation({
      query: (id) => ({ url: `/agents/${id}/retire`, method: 'POST' }),
      invalidatesTags: ['Agent'],
    }),

    // Administrators
    getUsers: b.query({
      query: () => '/users',
      providesTags: ['User'],
    }),
    createUser: b.mutation({
      query: (body) => ({ url: '/users', method: 'POST', body }),
      invalidatesTags: ['User'],
    }),
    updateUser: b.mutation({
      query: ({ id, ...body }) => ({ url: `/users/${id}`, method: 'PATCH', body }),
      invalidatesTags: ['User'],
    }),

    // Active sessions
    getSessions: b.query({
      query: () => '/sessions',
      providesTags: ['Session'],
    }),
    revokeSession: b.mutation({
      query: (id) => ({ url: `/sessions/${encodeURIComponent(id)}`, method: 'DELETE' }),
      invalidatesTags: ['Session'],
    }),

    // Protected content (IDM fingerprinting registry)
    getCollections: b.query({
      query: () => '/protected/collections',
      providesTags: ['ProtectedCollection'],
    }),
    createCollection: b.mutation({
      query: (body) => ({ url: '/protected/collections', method: 'POST', body }),
      invalidatesTags: ['ProtectedCollection'],
    }),
    getProtectedDocuments: b.query({
      query: (collectionId) => ({
        url: '/protected/documents',
        params: collectionId ? { collectionId } : {},
      }),
      providesTags: ['ProtectedDocument'],
    }),
    getProtectedDocument: b.query({
      query: (id) => `/protected/documents/${id}`,
      providesTags: (result, error, id) => [{ type: 'ProtectedDocument', id }],
    }),
    getIndexStatus: b.query({
      query: () => '/protected/index',
      providesTags: ['IndexStatus'],
    }),
    // Raw-bytes upload: the document body IS the request body; metadata rides
    // the query string + X-Filename header (see routes/protected.js).
    registerDocument: b.mutation({
      query: ({ collectionId, title, file }) => ({
        url: '/protected/documents',
        params: { collectionId, title },
        method: 'POST',
        body: file,
        headers: {
          'content-type': 'application/octet-stream',
          'x-filename': file.name,
        },
      }),
      invalidatesTags: ['ProtectedDocument', 'ProtectedCollection', 'IndexStatus'],
    }),
    compileIndex: b.mutation({
      query: () => ({ url: '/protected/index/compile', method: 'POST' }),
      invalidatesTags: ['IndexStatus'],
    }),

    // Audit log
    getAuditLog: b.query({
      query: (params = {}) => ({ url: '/audit', params }),
      providesTags: ['Audit'],
    }),
    verifyAuditChain: b.query({
      query: () => '/audit/verify',
      providesTags: ['Audit'],
    }),
  }),
})

export const {
  useGetEnrollmentTokensQuery,
  useCreateEnrollmentTokenMutation,
  useRevokeEnrollmentTokenMutation,
  useGetAgentsQuery,
  useRetireAgentMutation,
  useGetUsersQuery,
  useCreateUserMutation,
  useUpdateUserMutation,
  useGetSessionsQuery,
  useRevokeSessionMutation,
  useGetAuditLogQuery,
  useVerifyAuditChainQuery,
  useGetCollectionsQuery,
  useCreateCollectionMutation,
  useGetProtectedDocumentsQuery,
  useGetProtectedDocumentQuery,
  useRegisterDocumentMutation,
  useCompileIndexMutation,
  useGetIndexStatusQuery,
} = apiSlice
