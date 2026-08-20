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
  tagTypes: ['EnrollmentToken', 'Agent', 'User', 'Session', 'Audit', 'ProtectedCollection', 'ProtectedDocument', 'IndexStatus', 'Incident', 'TrustedDestination', 'TrustedReader', 'ReadDenyPolicy', 'Group'],
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

    // Detection incidents (the "which file was blocked" console feed)
    getIncidents: b.query({
      // `params` may carry channel, status, agentId, q, limit, offset.
      query: (params = {}) => ({ url: '/incidents', params }),
      providesTags: ['Incident'],
    }),
    getIncident: b.query({
      query: (id) => `/incidents/${id}`,
      // Detail resolves match ranges + is audited server-side; keep it fresh.
      providesTags: (result, error, id) => [{ type: 'Incident', id }],
    }),
    updateIncidentStatus: b.mutation({
      query: ({ id, ...body }) => ({ url: `/incidents/${id}/status`, method: 'PATCH', body }),
      invalidatesTags: (result, error, { id }) => [{ type: 'Incident', id }, 'Incident'],
    }),

    // Encrypt-on-write: trusted destinations (whitelisted USB devices) + org keys.
    getTrustedDestinations: b.query({
      query: () => '/encryption/trusted-destinations',
      transformResponse: (res) => res?.destinations || [],
      providesTags: ['TrustedDestination'],
    }),
    createTrustedDestination: b.mutation({
      // body carries { channel, matcher, mode, onBlockBand, keyId, note } — the
      // whole form body is forwarded, so onBlockBand ('block' | 'seal') rides along.
      query: (body) => ({ url: '/encryption/trusted-destinations', method: 'POST', body }),
      invalidatesTags: ['TrustedDestination'],
    }),
    deleteTrustedDestination: b.mutation({
      query: (id) => ({ url: `/encryption/trusted-destinations/${id}`, method: 'DELETE' }),
      invalidatesTags: ['TrustedDestination'],
    }),
    getEncryptionKeys: b.query({
      query: () => '/encryption/keys',
      transformResponse: (res) => res?.keys || [],
    }),

    // Read-deny allowlist posture: the sanctioned-reader allowlist (which apps
    // may read sensitive content locally). Every other process is treated as an
    // untrusted reader and denied the read of sensitive files on endpoints.
    getTrustedReaders: b.query({
      // groupId: undefined => all; 'global' => global readers; <n> => that group's.
      query: (groupId) => ({
        url: '/trusted-readers',
        params: groupId !== undefined && groupId !== null && groupId !== '' ? { groupId } : {},
      }),
      transformResponse: (res) => res?.readers || [],
      providesTags: ['TrustedReader'],
    }),
    createTrustedReader: b.mutation({
      // body: { matchType: 'publisher'|'path'|'name', value, note? }
      query: (body) => ({ url: '/trusted-readers', method: 'POST', body }),
      invalidatesTags: ['TrustedReader'],
    }),
    deleteTrustedReader: b.mutation({
      query: (id) => ({ url: `/trusted-readers/${id}`, method: 'DELETE' }),
      invalidatesTags: ['TrustedReader'],
    }),

    // Read-deny policy — the endpoint mode/posture/scope the agent applies to the
    // kernel driver. The console is the single source of truth; agents pull + apply
    // it, so the admin never touches the command line.
    getReadDenyPolicy: b.query({
      query: () => '/read-deny-policy',
      transformResponse: (res) => res?.policy || null,
      providesTags: ['ReadDenyPolicy'],
    }),
    updateReadDenyPolicy: b.mutation({
      // body: { mode, posture, scanFixed, watchPaths, failBlock, readersAuthority }
      query: (body) => ({ url: '/read-deny-policy', method: 'PUT', body }),
      invalidatesTags: ['ReadDenyPolicy'],
    }),

    // Endpoint groups — per-machine/per-group policy targeting. The Default group
    // holds every unassigned machine and uses the global read-deny policy.
    getGroups: b.query({
      query: () => '/groups',
      transformResponse: (res) => res?.groups || [],
      providesTags: ['Group'],
    }),
    createGroup: b.mutation({
      query: (body) => ({ url: '/groups', method: 'POST', body }),
      invalidatesTags: ['Group'],
    }),
    updateGroup: b.mutation({
      query: ({ id, ...body }) => ({ url: `/groups/${id}`, method: 'PUT', body }),
      invalidatesTags: ['Group'],
    }),
    deleteGroup: b.mutation({
      query: (id) => ({ url: `/groups/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Group', 'Agent'],
    }),

    // Per-group read-deny policy (Default group edits the global row). Envelope:
    // { policy, group, inheritsDefault, hasOverride }.
    getGroupReadDenyPolicy: b.query({
      query: (groupId) => `/read-deny-policy/group/${groupId}`,
      providesTags: (result, error, groupId) => [{ type: 'ReadDenyPolicy', id: `group-${groupId}` }],
    }),
    updateGroupReadDenyPolicy: b.mutation({
      query: ({ groupId, ...body }) => ({ url: `/read-deny-policy/group/${groupId}`, method: 'PUT', body }),
      invalidatesTags: (result, error, { groupId }) => [
        { type: 'ReadDenyPolicy', id: `group-${groupId}` },
        'ReadDenyPolicy',
        'Group',
      ],
    }),
    resetGroupReadDenyPolicy: b.mutation({
      query: (groupId) => ({ url: `/read-deny-policy/group/${groupId}`, method: 'DELETE' }),
      invalidatesTags: (result, error, groupId) => [
        { type: 'ReadDenyPolicy', id: `group-${groupId}` },
        'Group',
      ],
    }),

    // Assign an endpoint to a group (fleet management; agents.manage).
    assignAgentGroup: b.mutation({
      query: ({ id, groupId }) => ({ url: `/agents/${id}/group`, method: 'PUT', body: { groupId } }),
      invalidatesTags: ['Agent', 'Group'],
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
  useGetIncidentsQuery,
  useGetIncidentQuery,
  useUpdateIncidentStatusMutation,
  useGetTrustedDestinationsQuery,
  useCreateTrustedDestinationMutation,
  useDeleteTrustedDestinationMutation,
  useGetEncryptionKeysQuery,
  useGetTrustedReadersQuery,
  useCreateTrustedReaderMutation,
  useDeleteTrustedReaderMutation,
  useGetReadDenyPolicyQuery,
  useUpdateReadDenyPolicyMutation,
  useGetGroupsQuery,
  useCreateGroupMutation,
  useUpdateGroupMutation,
  useDeleteGroupMutation,
  useGetGroupReadDenyPolicyQuery,
  useUpdateGroupReadDenyPolicyMutation,
  useResetGroupReadDenyPolicyMutation,
  useAssignAgentGroupMutation,
} = apiSlice
