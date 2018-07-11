﻿namespace Rasa.Managers
{
    using Data;
    using Database.Tables.Character;
    using Database.Tables.World;
    using Game;
    using Packets.Game.Client;
    using Packets.Game.Server;
    using Packets.MapChannel.Server;
    using Structures;

    public class CharacterManager
    {
        public const uint SelectionPodStartEntityId = 100;
        public const byte MaxSelectionPods = 16;

        private static CharacterManager _instance;
        private static readonly object InstanceLock = new object();

        private readonly object CreateLock = new object();

        public static CharacterManager Instance
        {
            get
            {
                if (_instance != null)
                    return _instance;

                lock (InstanceLock)
                {
                    if (_instance == null)
                        _instance = new CharacterManager();
                }

                return _instance;
            }
        }

        private CharacterManager()
        {
        }

        public void StartCharacterSelection(Client client)
        {
            if (client.State != ClientState.LoggedIn)
                return;

            client.CallMethod(SysEntity.ClientMethodId, new BeginCharacterSelectionPacket(client.AccountEntry.FamilyName, client.AccountEntry.CharacterCount > 0, client.AccountEntry.Id));

            var charactersBySlot = CharacterTable.ListCharactersBySlot(client.AccountEntry.Id);

            for (byte i = 1; i <= MaxSelectionPods; ++i)
            {
                if (charactersBySlot.ContainsKey(i))
                    SendCharacterInfo(client, i, charactersBySlot[i], true);
                else
                    SendCharacterInfo(client, i, null, true);
            }

            client.State = ClientState.CharacterSelection;
			
			// get userOptions
            var optionsList = UserOptionsTable.GetUserOptions(client.AccountEntry.Id);

            foreach (var userOption in optionsList)
                client.UserOptions.Add(new UserOptions((UserOption)userOption.OptionId, userOption.Value));

            client.CallMethod(SysEntity.ClientMethodId, new UserOptionsPacket(client.UserOptions));
        }

        public void RequestCharacterName(Client client, int gender)
        {
            client.CallMethod(SysEntity.ClientMethodId, new GeneratedCharacterNamePacket
            {
                Name = PlayerRandomNameTable.GetRandom((PlayerRandomNameTable.Gender) gender, PlayerRandomNameTable.NameType.First) ?? (gender == 0 ? "Richard" : "Rachel")
            });
        }

        public void RequestFamilyName(Client client)
        {
            client.CallMethod(SysEntity.ClientMethodId, new GeneratedFamilyNamePacket
            {
                Name = PlayerRandomNameTable.GetRandom(PlayerRandomNameTable.Gender.Neutral, PlayerRandomNameTable.NameType.Last) ?? "Garriott"
            });
        }

        public void RequestCreateCharacterInSlot(Client client, RequestCreateCharacterInSlotPacket packet)
        {
            var result = packet.Validate();
            if (result != CreateCharacterResult.Success)
            {
                SendCharacterCreateFailed(client, result);
                return;
            }

            CharacterEntry entry;
            bool changeFamilyName = false;

            lock (CreateLock)
            {
                if (!string.IsNullOrWhiteSpace(client.AccountEntry.FamilyName) && packet.FamilyName != client.AccountEntry.FamilyName)
                {
                    if (client.AccountEntry.CharacterCount == 0)
                    {
                        changeFamilyName = true;
                    }
                    else
                    {
                        SendCharacterCreateFailed(client, CreateCharacterResult.InvalidCharacterName);
                        return;
                    }
                }

                if ((string.IsNullOrWhiteSpace(client.AccountEntry.FamilyName) || packet.FamilyName != client.AccountEntry.FamilyName))
                {
                    var familyNameOwnerAccount = GameAccountTable.GetAccountByFamilyName(packet.FamilyName);

                    if (familyNameOwnerAccount != null && client.AccountEntry.Id != familyNameOwnerAccount.Id)
                    {
                        SendCharacterCreateFailed(client, CreateCharacterResult.FamilyNameReserved);
                        return;
                    }
                    
                }

                entry = new CharacterEntry
                {
                    AccountId = client.AccountEntry.Id,
                    Slot = packet.SlotNum,
                    Name = packet.CharacterName,
                    Race = (byte) packet.RaceId,
                    Class = 1,
                    Scale = packet.Scale,
                    Gender = packet.Gender,
                    Experience = 0,
                    Level = 1,
                    Body = 0,
                    Mind = 0,
                    Spirit = 0,
                    MapContextId = 0,
                    CoordX = 0,
                    CoordY = 0,
                    CoordZ = 0,
                    Rotation = 0
                };

                if (!CharacterTable.CreateCharacter(entry))
                {
                    SendCharacterCreateFailed(client, CreateCharacterResult.TechnicalDifficulty);
                    return;
                }

                foreach (var data in packet.AppearanceData)
                    CharacterAppearanceTable.AddAppearance(entry.Id, data.Value.GetDatabaseEntry());

                if (string.IsNullOrWhiteSpace(client.AccountEntry.FamilyName) || changeFamilyName)
                {
                    client.AccountEntry.FamilyName = packet.FamilyName;

                    GameAccountTable.UpdateAccount(client.AccountEntry);
                }
            }

            client.CallMethod(SysEntity.ClientMethodId, new CharacterCreateSuccessPacket(packet.SlotNum, packet.FamilyName));
            ++client.AccountEntry.CharacterCount;

            SendCharacterInfo(client, packet.SlotNum, entry, false);
        }

        public void RequestDeleteCharacterInSlot(Client client, RequestDeleteCharacterInSlotPacket packet)
        {
            try
            {
                var charactersBySlot = CharacterTable.ListCharactersBySlot(client.AccountEntry.Id);
                if (charactersBySlot.ContainsKey(packet.Slot))
                {
                    CharacterTable.DeleteCharacter(charactersBySlot[packet.Slot].Id);

                    client.CallMethod(SysEntity.ClientMethodId, new CharacterDeleteSuccessPacket(--client.AccountEntry.CharacterCount > 0));

                    SendCharacterInfo(client, packet.Slot, null, false);

                    return;
                }
            }
            catch
            {
                client.CallMethod(SysEntity.ClientMethodId, new DeleteCharacterFailedPacket());
            }
        }

        private void SendCharacterCreateFailed(Client client, CreateCharacterResult result)
        {
            client.CallMethod(SysEntity.ClientMethodId, new UserCreationFailedPacket(result));
        }

        private void SendCharacterInfo(Client client, byte slot, CharacterEntry data, bool sendPodCreate)
        {
            if (!sendPodCreate)
            {
                client.CallMethod(SelectionPodStartEntityId + slot, new CharacterInfoPacket(slot, slot == client.AccountEntry.SelectedSlot, client.AccountEntry.FamilyName, data));
                return;
            }

            var newEntityPacket = new CreatePhysicalEntityPacket(SelectionPodStartEntityId + slot, EntityClassId.CharacterSelectionPod);

            newEntityPacket.EntityData.Add(new CharacterInfoPacket(slot, slot == client.AccountEntry.SelectedSlot, client.AccountEntry.FamilyName, data));

            client.CallMethod(SysEntity.ClientMethodId, newEntityPacket);
        }

        #region InGame
        public void UpdateCharacter(Client client, int job)
        {
            switch (job)
            {
                case 1: // update level
                    break;
                case 2: // updarte credits
                    //CharacterTable.UpdateCharacterCredits(client.AccountEntry.Id, client.MapClient.Player.CharacterSlot, client.MapClient.Player.Credits);
                    break;
                case 3: // update prestige
                    break;
                case 4: // update experience
                    break;
                case 5: // update possition
                        /*CharacterTable.UpdateCharacterPos(
                            client.AccountEntry.Id,
                            client.MapClient.Player.CharacterSlot,
                            client.MapClient.Player.Actor.Position.PosX,
                            client.MapClient.Player.Actor.Position.PosY,
                            client.MapClient.Player.Actor.Position.PosZ,
                            client.MapClient.Player.Actor.Rotation.W ,  // ToDo rotation
                            client.MapClient.Player.Actor.MapContextId
                            ); */
                    break;
                case 6: // update stats
                    break;
                case 7: // update login
                    //CharacterTable.UpdateCharacterLogin(client.AccountEntry.Id, client.MapClient.Player.CharacterSlot, client.MapClient.Player.LoginTime); // ToDO LoginTime need to be changed with proper value
                    break;
                case 8: // update logos
                    break;
                case 9: // update class
                    break;
                default:
                    break;

            }
        }
        #endregion
    }
}
