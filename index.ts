// Fonction Supabase Edge Function : create-user
// Permet à un administrateur connecté de créer un nouveau compte
// (email + mot de passe) sans passer par le tableau de bord Supabase.
//
// Déploiement : voir le fichier README-fonction.md à côté de ce fichier.

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) throw new Error('Non authentifié')

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

    // 1) Vérifie que la personne qui appelle est bien connectée
    const callerClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    })
    const { data: { user }, error: userErr } = await callerClient.auth.getUser()
    if (userErr || !user) throw new Error('Non authentifié')

    // 2) Vérifie que c'est bien un administrateur (avec les droits complets)
    const admin = createClient(supabaseUrl, serviceKey)
    const { data: profile } = await admin.from('profiles').select('role').eq('id', user.id).single()
    if (!profile || profile.role !== 'admin') {
      throw new Error("Seul un administrateur peut créer un compte")
    }

    // 3) Crée le nouvel utilisateur
    const { name, email, password, role } = await req.json()
    if (!name || !email || !password) throw new Error('Nom, email et mot de passe requis')
    if (password.length < 6) throw new Error('Le mot de passe doit faire au moins 6 caractères')

    const { data: created, error: createErr } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { name },
    })
    if (createErr) throw createErr

    // Le profil est créé automatiquement par le trigger (rôle "vendeur" par défaut) :
    // on met à jour son nom et son rôle choisi.
    await admin.from('profiles').update({ name, role: role || 'vendeur' }).eq('id', created.user.id)

    return new Response(JSON.stringify({ ok: true }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})
