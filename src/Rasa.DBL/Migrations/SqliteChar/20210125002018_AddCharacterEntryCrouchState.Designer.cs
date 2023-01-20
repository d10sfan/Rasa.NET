﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Rasa.Context.Char;

namespace Rasa.Migrations.SqliteChar
{
    [DbContext(typeof(SqliteCharContext))]
    [Migration("20210125002018_AddCharacterEntryCrouchState")]
    partial class AddCharacterEntryCrouchState
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "5.0.1");

            modelBuilder.Entity("Rasa.Structures.Char.CharacterAppearanceEntry", b =>
                {
                    b.Property<uint>("CharacterId")
                        .HasColumnType("integer")
                        .HasColumnName("character_id");

                    b.Property<uint>("Slot")
                        .HasColumnType("integer")
                        .HasColumnName("slot");

                    b.Property<uint>("Class")
                        .HasColumnType("int(11)")
                        .HasColumnName("class");

                    b.Property<uint>("Color")
                        .HasColumnType("int(11)")
                        .HasColumnName("color");

                    b.HasKey("CharacterId", "Slot");

                    b.ToTable("character_appearance");
                });

            modelBuilder.Entity("Rasa.Structures.Char.CharacterEntry", b =>
                {
                    b.Property<uint>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer")
                        .HasColumnName("id");

                    b.Property<uint>("AccountId")
                        .HasColumnType("integer")
                        .HasColumnName("account_id");

                    b.Property<uint>("Body")
                        .HasColumnType("int(11)")
                        .HasColumnName("body");

                    b.Property<uint>("Class")
                        .HasColumnType("int(11)")
                        .HasColumnName("class");

                    b.Property<uint>("CloneCredits")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int(11)")
                        .HasDefaultValue(0u)
                        .HasColumnName("clone_credits");

                    b.Property<double>("CoordX")
                        .HasColumnType("double")
                        .HasColumnName("coord_x");

                    b.Property<double>("CoordY")
                        .HasColumnType("double")
                        .HasColumnName("coord_y");

                    b.Property<double>("CoordZ")
                        .HasColumnType("double")
                        .HasColumnName("coord_z");

                    b.Property<DateTime>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("datetime('now')");

                    b.Property<byte>("CrouchState")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("tinyint(3)")
                        .HasDefaultValue((byte)0)
                        .HasColumnName("crouch_state");

                    b.Property<uint>("Experience")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int(11)")
                        .HasDefaultValue(0u)
                        .HasColumnName("experience");

                    b.Property<byte>("Gender")
                        .HasColumnType("bit")
                        .HasColumnName("gender");

                    b.Property<DateTime?>("LastLogin")
                        .IsRequired()
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT")
                        .HasColumnName("last_login")
                        .HasDefaultValueSql("datetime('now')");

                    b.Property<byte>("Level")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("tinyint(3)")
                        .HasDefaultValue((byte)1)
                        .HasColumnName("level");

                    b.Property<uint>("MapContextId")
                        .HasColumnType("int(11)")
                        .HasColumnName("map_context_id");

                    b.Property<uint>("Mind")
                        .HasColumnType("int(11)")
                        .HasColumnName("mind");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("varchar(64)")
                        .HasColumnName("name");

                    b.Property<uint>("NumLogins")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int(11)")
                        .HasDefaultValue(0u)
                        .HasColumnName("num_logins");

                    b.Property<byte>("Race")
                        .HasColumnType("tinyint(3)")
                        .HasColumnName("race");

                    b.Property<double>("Rotation")
                        .HasColumnType("double")
                        .HasColumnName("rotation");

                    b.Property<byte>("RunState")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("tinyint(3)")
                        .HasDefaultValue((byte)1)
                        .HasColumnName("run_state");

                    b.Property<double>("Scale")
                        .HasColumnType("double")
                        .HasColumnName("scale");

                    b.Property<byte>("Slot")
                        .HasColumnType("tinyint(3)")
                        .HasColumnName("slot");

                    b.Property<uint>("Spirit")
                        .HasColumnType("int(11)")
                        .HasColumnName("spirit");

                    b.Property<uint>("TotalTimePlayed")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int(11)")
                        .HasDefaultValue(0u)
                        .HasColumnName("total_time_played");

                    b.HasKey("Id");

                    b.HasIndex(new[] { "AccountId" }, "character_index_account");

                    b.ToTable("character");
                });

            modelBuilder.Entity("Rasa.Structures.Char.ClanEntry", b =>
                {
                    b.Property<uint>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer")
                        .HasColumnName("id");

                    b.Property<DateTime>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("datetime('now')");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("varchar(100)")
                        .HasColumnName("name");

                    b.HasKey("Id");

                    b.ToTable("clan");
                });

            modelBuilder.Entity("Rasa.Structures.Char.ClanMemberEntry", b =>
                {
                    b.Property<uint>("ClanId")
                        .HasColumnType("integer")
                        .HasColumnName("clan_id");

                    b.Property<uint>("CharacterId")
                        .HasColumnType("integer")
                        .HasColumnName("character_id");

                    b.Property<byte>("Rank")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("tinyint(3)")
                        .HasDefaultValue((byte)0)
                        .HasColumnName("rank");

                    b.HasKey("ClanId", "CharacterId");

                    b.HasIndex(new[] { "CharacterId" }, "clan_member_index_character")
                        .IsUnique();

                    b.ToTable("clan_member");
                });

            modelBuilder.Entity("Rasa.Structures.Char.GameAccountEntry", b =>
                {
                    b.Property<uint>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer")
                        .HasColumnName("id")
                        .HasAnnotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.None);

                    b.Property<bool>("CanSkipBootcamp")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bit")
                        .HasDefaultValue(false)
                        .HasColumnName("can_skip_bootcamp");

                    b.Property<DateTime>("CreatedAt")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT")
                        .HasColumnName("created_at")
                        .HasDefaultValueSql("datetime('now')");

                    b.Property<string>("Email")
                        .IsRequired()
                        .HasColumnType("varchar(255)")
                        .HasColumnName("email");

                    b.Property<string>("FamilyName")
                        .IsRequired()
                        .ValueGeneratedOnAdd()
                        .HasColumnType("varchar(64)")
                        .HasDefaultValue("")
                        .HasColumnName("family_name");

                    b.Property<string>("LastIp")
                        .IsRequired()
                        .ValueGeneratedOnAdd()
                        .HasColumnType("varchar(15)")
                        .HasDefaultValue("0.0.0.0")
                        .HasColumnName("last_ip");

                    b.Property<DateTime>("LastLogin")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("TEXT")
                        .HasColumnName("last_login")
                        .HasDefaultValueSql("datetime('now')");

                    b.Property<byte>("Level")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("tinyint(3)")
                        .HasDefaultValue((byte)0)
                        .HasColumnName("level");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("varchar(64)")
                        .HasColumnName("name");

                    b.Property<byte>("SelectedSlot")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("tinyint(3)")
                        .HasDefaultValue((byte)0)
                        .HasColumnName("selected_slot");

                    b.HasKey("Id");

                    b.ToTable("account");
                });

            modelBuilder.Entity("Rasa.Structures.Char.CharacterAppearanceEntry", b =>
                {
                    b.HasOne("Rasa.Structures.Char.CharacterEntry", "Character")
                        .WithMany("CharacterAppearance")
                        .HasForeignKey("CharacterId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.Navigation("Character");
                });

            modelBuilder.Entity("Rasa.Structures.Char.CharacterEntry", b =>
                {
                    b.HasOne("Rasa.Structures.Char.GameAccountEntry", "GameAccount")
                        .WithMany("Characters")
                        .HasForeignKey("AccountId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.Navigation("GameAccount");
                });

            modelBuilder.Entity("Rasa.Structures.Char.ClanMemberEntry", b =>
                {
                    b.HasOne("Rasa.Structures.Char.CharacterEntry", "Character")
                        .WithOne("MemberOfClan")
                        .HasForeignKey("Rasa.Structures.Char.ClanMemberEntry", "CharacterId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.HasOne("Rasa.Structures.Char.ClanEntry", "Clan")
                        .WithMany("Members")
                        .HasForeignKey("ClanId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.Navigation("Character");

                    b.Navigation("Clan");
                });

            modelBuilder.Entity("Rasa.Structures.Char.CharacterEntry", b =>
                {
                    b.Navigation("CharacterAppearance");

                    b.Navigation("MemberOfClan");
                });

            modelBuilder.Entity("Rasa.Structures.Char.ClanEntry", b =>
                {
                    b.Navigation("Members");
                });

            modelBuilder.Entity("Rasa.Structures.Char.GameAccountEntry", b =>
                {
                    b.Navigation("Characters");
                });
#pragma warning restore 612, 618
        }
    }
}
